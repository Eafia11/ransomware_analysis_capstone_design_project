#!/usr/bin/env python3
"""Manage disposable Windows EC2 sandbox instances for NetGuardian."""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from typing import Any


MANAGED_BY = "netguardian-ec2-sandbox"
DEFAULT_NAME = "netguardian-windows-sandbox"


def load_boto3() -> Any:
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "boto3 is required. Install it with: python -m pip install boto3"
        ) from exc
    return boto3


def env_list(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def require_value(value: str | None, message: str) -> str:
    if value:
        return value
    raise SystemExit(message)


def ec2_client(region: str) -> Any:
    return load_boto3().client("ec2", region_name=region)


def ec2_resource(region: str) -> Any:
    return load_boto3().resource("ec2", region_name=region)


def create_ami(args: argparse.Namespace) -> None:
    client = ec2_client(args.region)
    response = client.create_image(
        InstanceId=args.instance_id,
        Name=args.name,
        Description=args.description,
        NoReboot=args.no_reboot,
        TagSpecifications=[
            {
                "ResourceType": "image",
                "Tags": [
                    {"Key": "Name", "Value": args.name},
                    {"Key": "Project", "Value": "netguardian"},
                    {"Key": "ManagedBy", "Value": MANAGED_BY},
                ],
            }
        ],
    )
    print(response["ImageId"])


def launch_instance(args: argparse.Namespace) -> None:
    image_id = require_value(
        args.ami_id or os.getenv("NG_WINDOWS_AMI_ID"),
        "Missing AMI ID. Pass --ami-id or set NG_WINDOWS_AMI_ID.",
    )
    key_name = require_value(
        args.key_name or os.getenv("NG_WINDOWS_KEY_NAME"),
        "Missing key pair. Pass --key-name or set NG_WINDOWS_KEY_NAME.",
    )
    security_group_ids = args.security_group_ids or env_list("NG_WINDOWS_SECURITY_GROUP_IDS")
    if not security_group_ids:
        raise SystemExit(
            "Missing security groups. Pass --security-group-ids or set "
            "NG_WINDOWS_SECURITY_GROUP_IDS."
        )

    run_args: dict[str, Any] = {
        "ImageId": image_id,
        "InstanceType": args.instance_type,
        "MinCount": 1,
        "MaxCount": 1,
        "KeyName": key_name,
        "SecurityGroupIds": security_group_ids,
        "TagSpecifications": [
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": args.name},
                    {"Key": "Project", "Value": "netguardian"},
                    {"Key": "ManagedBy", "Value": MANAGED_BY},
                ],
            }
        ],
    }

    subnet_id = args.subnet_id or os.getenv("NG_WINDOWS_SUBNET_ID")
    if subnet_id:
        run_args["SubnetId"] = subnet_id

    if args.user_data:
        with open(args.user_data, "r", encoding="utf-8") as user_data:
            run_args["UserData"] = user_data.read()

    resource = ec2_resource(args.region)
    instance = resource.create_instances(**run_args)[0]
    print(instance.id)

    if args.wait:
        instance.wait_until_running()
        instance.reload()
        print(instance.public_ip_address or "")


def instance_filters(args: argparse.Namespace) -> list[dict[str, Any]]:
    filters = [
        {"Name": "tag:Project", "Values": ["netguardian"]},
        {"Name": "instance-state-name", "Values": args.states},
    ]
    if args.managed_only:
        filters.append({"Name": "tag:ManagedBy", "Values": [MANAGED_BY]})
    return filters


def show_status(args: argparse.Namespace) -> None:
    client = ec2_client(args.region)
    if args.instance_id:
        response = client.describe_instances(InstanceIds=[args.instance_id])
    else:
        response = client.describe_instances(Filters=instance_filters(args))

    rows: list[tuple[str, str, str, str, str]] = []
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
            rows.append(
                (
                    instance["InstanceId"],
                    tags.get("Name", ""),
                    instance["State"]["Name"],
                    instance.get("PublicIpAddress", ""),
                    instance.get("PrivateIpAddress", ""),
                )
            )

    if not rows:
        print("No matching instances.")
        return

    print("INSTANCE_ID\tNAME\tSTATE\tPUBLIC_IP\tPRIVATE_IP")
    for row in rows:
        print("\t".join(row))


def terminate_instance(args: argparse.Namespace) -> None:
    client = ec2_client(args.region)
    client.terminate_instances(InstanceIds=[args.instance_id])
    print(args.instance_id)

    if args.wait:
        resource = ec2_resource(args.region)
        instance = resource.Instance(args.instance_id)
        instance.wait_until_terminated()
        print("terminated")


def wait_ssh(args: argparse.Namespace) -> None:
    deadline = time.time() + args.timeout
    last_error = ""
    while time.time() < deadline:
        try:
            with socket.create_connection((args.host, args.port), timeout=5):
                print("open")
                return
        except OSError as exc:
            last_error = str(exc)
            time.sleep(args.interval)
    raise SystemExit(f"SSH port did not open: {last_error}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create, launch, inspect, and terminate Windows EC2 sandboxes."
    )
    parser.add_argument(
        "--region",
        default=os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "ap-southeast-2")),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ami = subparsers.add_parser("create-ami", help="Create an AMI from a prepared instance.")
    ami.add_argument("--instance-id", required=True)
    ami.add_argument("--name", required=True)
    ami.add_argument("--description", default="NetGuardian Windows sandbox AMI")
    ami.add_argument("--no-reboot", action="store_true")
    ami.set_defaults(func=create_ami)

    launch = subparsers.add_parser("launch", help="Launch a disposable Windows sandbox.")
    launch.add_argument("--ami-id")
    launch.add_argument("--name", default=DEFAULT_NAME)
    launch.add_argument(
        "--instance-type",
        default=os.getenv("NG_WINDOWS_INSTANCE_TYPE", "t3.small"),
    )
    launch.add_argument("--key-name")
    launch.add_argument("--subnet-id")
    launch.add_argument("--security-group-ids", nargs="+")
    launch.add_argument("--user-data")
    launch.add_argument("--wait", action="store_true")
    launch.set_defaults(func=launch_instance)

    status = subparsers.add_parser("status", help="Show Windows sandbox instances.")
    status.add_argument("--instance-id")
    status.add_argument("--managed-only", action="store_true")
    status.add_argument(
        "--states",
        nargs="+",
        default=["pending", "running", "stopping", "stopped"],
    )
    status.set_defaults(func=show_status)

    terminate = subparsers.add_parser("terminate", help="Terminate a sandbox instance.")
    terminate.add_argument("--instance-id", required=True)
    terminate.add_argument("--wait", action="store_true")
    terminate.set_defaults(func=terminate_instance)

    ssh = subparsers.add_parser("wait-ssh", help="Wait until TCP SSH is reachable.")
    ssh.add_argument("--host", required=True)
    ssh.add_argument("--port", type=int, default=22)
    ssh.add_argument("--timeout", type=int, default=900)
    ssh.add_argument("--interval", type=int, default=10)
    ssh.set_defaults(func=wait_ssh)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
