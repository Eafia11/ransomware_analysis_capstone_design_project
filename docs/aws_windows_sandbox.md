# AWS Windows sandbox control

This project can manage disposable Windows EC2 analysis sandboxes from the
Ubuntu NetGuardian server. The script uses the AWS credentials configured on
the Ubuntu host, normally `~/.aws/credentials`, and does not store secrets in
the repository.

## What belongs in the AMI

Prepare one Windows instance with:

- OpenSSH Server enabled for `Administrator` access.
- Sysmon installed and running.
- Winlogbeat installed and configured to send to the Ubuntu Logstash host on
  TCP `5044`.
- Any malware-analysis tooling needed for the capstone demo.

Then create an AMI from that prepared instance:

```bash
python scripts/ec2_sandbox.py create-ami \
  --instance-id i-xxxxxxxxxxxxxxxxx \
  --name netguardian-windows-sandbox-YYYYMMDD
```

The AMI stores the Windows disk state. It does not store which security group
must be attached at launch time, so pass the security group when creating each
new sandbox instance.

## Ubuntu environment

Set these values on the Ubuntu server before launching instances:

```bash
export AWS_REGION=ap-southeast-2
export NG_WINDOWS_AMI_ID=ami-xxxxxxxxxxxxxxxxx
export NG_WINDOWS_KEY_NAME=netguardian-key
export NG_WINDOWS_SUBNET_ID=subnet-xxxxxxxxxxxxxxxxx
export NG_WINDOWS_SECURITY_GROUP_IDS=sg-xxxxxxxxxxxxxxxxx
export NG_WINDOWS_INSTANCE_TYPE=t3.small
```

The security group should allow SSH from the operator IP and outbound traffic
to the Ubuntu Logstash endpoint. The Ubuntu security group must allow inbound
TCP `5044` from the Windows sandbox.

## Launch and inspect

Launch a fresh Windows sandbox:

```bash
python scripts/ec2_sandbox.py launch --wait
```

Show active NetGuardian instances:

```bash
python scripts/ec2_sandbox.py status
```

Wait for SSH if the instance was launched without `--wait`:

```bash
python scripts/ec2_sandbox.py wait-ssh --host <WINDOWS_PUBLIC_IP>
```

Connect from your machine or the Ubuntu server:

```bash
ssh Administrator@<WINDOWS_PUBLIC_IP>
```

## Cleanup

Terminate a sandbox after each malware run:

```bash
python scripts/ec2_sandbox.py terminate \
  --instance-id i-xxxxxxxxxxxxxxxxx \
  --wait
```

Do not reuse a sandbox after running malware. Launch a new instance from the
prepared AMI for the next run.
