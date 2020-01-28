# kms-host-key

[EC2 Instance Connect][eic] filled a much-needed gap for AWS users who wanted a 
want to log into EC2 instances over SSH without the hassle of managing SSH keys.

The missing piece of the puzzle is authenticating the host you are logging into.
Even if you don't care about the possibility of a [MITM][mitm] attack, this message is
a pain. Especially if you are automating your SSH and don't have a TTY present
to type "yes":

> The authenticity of host '1.2.3.4 (1.2.3.4)' can't be established.
> RSA key fingerprint is SHA256:PMxq13AoZOG2KZ5qPaZCgMpzJx8gyKLxaE/e5Q//4GE.
> Are you sure you want to continue connecting (yes/no)? 

That's where `kms-host-key` comes in. Include it in your EC2 userdata script
and it requests that [AWS KMS][kms] sign the instance's host key. This means that you
and your colleagues can add a single line to your `~/.ssh/known_hosts` and never
seen that pesky warning again. That line would look something like:

    echo '@cert-authority * ssh-rsa AAAAB3NzaC1yc...' >> ~/.ssh/known_hosts 

## Usage

First, create an **RSA** KMS key with the following key policy:

```json
{
  "Version": "2012-10-17",
  "Id": "key-default-1",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_ACCOUNT_ID:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowAnyoneToPrintPubKey",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "kms:GetPublicKey",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-YOUR_ORG_ID"
        }
      }
    },
    {
      "Sid": "AllowEC2ToSignPartOne",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "kms:Sign",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-YOUR_ORG_ID"
        }
      }
    },
    {
      "Sid": "AllowEC2ToSignPartTwo",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "kms:Sign",
      "Resource": "*",
      "Condition": {
        "Null": {
          "ec2:SourceInstanceARN": "true"
        }
      }
    }
  ]
}
```

It is also recommended to give it an alias of `alias/hostkeysigner` - this is 
the default used by `kms-host-key` and will require less configuration on your
behalf.

Next, add the following to your userdata:

```shell script
# download
curl -o kms-host-key.tgz -L https://github.com/glassechidna/kms-host-key/releases/download/0.1.0/kms-host-key_0.1.0_linux_amd64.tar.gz
tar -xvf kms-host-key.tgz

# run
./kms-host-key -g >> /etc/ssh/ssh_host_rsa_key-cert.pub
echo 'HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub' >> /etc/ssh/sshd_config
service sshd restart

# cleanup
rm kms-host-key kms-host-key.tgz
```

Finally, download `kms-host-key` on your laptop and run this:

    kms-host-key -c >> ~/.ssh/known_hosts
    
You're ready to get started!

## Cross-account/region considerations

By default, the above KMS key policy is sufficient to grant instances in the same
*account* permission to create signed host keys. If you wish for instances in
other accounts (but still within the same AWS organization) to be able to sign
their host keys, they will need to have `kms:Sign` permissions in their instance
profiles' IAM roles.

Likewise, by default `kms-host-key` assumes that an unqualified key ID or alias
refers to a key in the same region as the instance. This behaviour can be changed
by specifying a full key ARN, e.g. `arn:aws:kms:us-east-1:0123456789012:alias/hostkeysigner`
which will work across regions.

[eic]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-methods.html
[mitm]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
[kms]: https://aws.amazon.com/kms/
