# Whitelist Atlassian IPs to AWS Security Group

This simple python project contains methods for creating and maintaining AWS security groups with Ingress rules containing
the Atlassian IP blocks as reported from their Web URL: https://ip-ranges.atlassian.com.

## Description

The program gets the ip blocks from the Atlassian url and stores the output to an object, then it counts the items and 
creates a number of security groups to add the ip blocks. The program takes into account the quota limit of 60 rules per
SG and it creates a new SG to store the additional rules.

The SGs that are created have the names `bitbucket-x` where x is an index starting from 0.

If running for the first time the program will create and populate the SGs with Atlassian Cidrs for Ipv4 and Ipv6. If 
running for update then the program will check the existing bitbucket SGs and sync them with the current IP list from the
Atlassian Web URL. Sync means that it will revoke access to IPs that are no longer listed in Web URL and will grant 
access to new IPs that are not included in the SGs.

## Use Cases

This program was developed to offer a quick solution when running a Jenkins server in AWS EC2 and do not want to expose 
it to the Internet. Though It must somehow receive the Bitbucket web-hooks. After creating and applying the security groups
to the Jenkins EC2 Instance, the Jenkins server it remains secure and it can listen for Bitbucket web-hooks.

## How to use it 

The program uses the `create_security_groups(session, vpc_id)` method to create or update the bitbucket security groups.
It takes two arguments, an AWS session object and the AWS VPC Id where the security groups will be created.

Example:
```python
import main
import boto3
session = boto3.Session(region_name='eu-central-1',profile_name='dev')
vpc_id = 'vpc-xxxxxxxxxxxx'
main.create_security_groups(session,vpc_id)
```

Support methods can be used separately. E.g. to get the Atlassian IPs:
```python
import main
main.get_atlassian_ips()
['2600:1f18:2146:e300::/56', '52.41.219.63/32', '34.216.18.129/32', '13.236.8.128/25', '2406:da1c:1e0:a200::/56', '2a05:d014:f99:dd00::/56', '2a05:d018:34d:5800::/56', '18.246.31.128/25', '34.236.25.177/32', '185.166.140.0/22', '34.199.54.113/32', '2600:1f1c:cc5:2300::/56', '2600:1f14:824:300::/56', '35.155.178.254/32', '52.204.96.37/32', '2406:da18:809:e00::/56', '35.160.177.10/32', '52.203.14.55/32', '18.184.99.128/25', '2401:1d80:3000::/36', '52.215.192.128/25', '104.192.136.0/21', '18.205.93.0/27', '35.171.175.212/32', '18.136.214.0/25', '52.202.195.162/32', '13.52.5.0/25', '34.218.168.212/32', '18.234.32.128/25', '34.218.156.209/32', '52.54.90.98/32', '34.232.119.183/32', '34.232.25.90/32']
```

### Maintenance

It is wise to run it every now and then so to keep the SGs updated.