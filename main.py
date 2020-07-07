import json
import boto3
from urllib.request import Request, urlopen
from botocore.exceptions import ClientError


def get_atlassian_ips():

    atlassian_url = "https://ip-ranges.atlassian.com"
    req = Request(atlassian_url, headers={"Content-Type": "application/json"})

    with urlopen(req) as r:
        response = json.loads(r.read().decode())

    iplist = list(map(lambda x: x['cidr'],response['items']))

    return iplist


def get_bitbucket_sg_ids(security_groups_list):

    bitbucket_sgs = []

    # If Bitbucket security groups exist already, append their id to bitbucket_sgs list.
    for item in security_groups_list:
        if 'bitbucket' in list(item.keys())[0]:
            bitbucket_sgs.append(list(item.values())[0])

    return bitbucket_sgs


def create_security_groups(session, vpc_id):

    ec2_client=session.client('ec2')
    ip_list = get_atlassian_ips()

    response = ec2_client.describe_security_groups()
    sgs = list(map(lambda x: {x['GroupName']: x['GroupId']}, response['SecurityGroups']))

    bitbucket_sgs = get_bitbucket_sg_ids(sgs)

    number_of_security_groups = round(.5 + len(ip_list) / 60)  # Create more security groups if ip number > 60

    # If Security groups do not exist, create them.
    if len(bitbucket_sgs) < number_of_security_groups:
        for i in range(number_of_security_groups):
            if not f'bitbucket-{i}' in map(lambda x: x.keys(),sgs):
                response = ec2_client.create_security_group(
                    Description= f'Bitbucket SG Access - {i}',
                    GroupName= f'bitbucket-{i}',
                    VpcId=vpc_id,
                )

                bitbucket_sgs.append(response['GroupId'])

        count =1
        index = 0

        ip_ranges = []
        ip_v6_ranges = []

        for ip in ip_list:
            group_id = bitbucket_sgs[index]

            if count < len(ip_list)/number_of_security_groups and ip != ip_list[-1]:
                if is_v4(ip):
                    ip_ranges.append({'CidrIp': ip, 'Description': 'Bitbucket cidr'})
                else:
                    ip_v6_ranges.append({'CidrIpv6': ip, 'Description': 'Bitbucket cidr'})
            else:
                ip_permissions = [{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': ip_ranges,
                    'Ipv6Ranges': ip_v6_ranges}]

                ec2 = boto3.resource('ec2', region_name='eu-central-1')
                sg = ec2.SecurityGroup(group_id)
                try:
                    request = sg.authorize_ingress(IpPermissions=ip_permissions)
                    print(request)
                except Exception as e:
                    print(e)

                count=0
                index+=1
                ip_ranges = []
                ip_v6_ranges = []
            count+=1
    else:
        update_security_groups(bitbucket_sgs,session)


def return_all_cidrs_from_sg(sec_group):
    cidrs = []
    ipv4_permisions = list(map(lambda x: x['IpRanges'], sec_group.ip_permissions))
    ipv6_permisions = list(map(lambda x: x['Ipv6Ranges'], sec_group.ip_permissions))

    for permission in ipv4_permisions:
        cidrs += list(map(lambda x: x['CidrIp'], permission))

    for permission in ipv6_permisions:
        cidrs += list(map(lambda x: x.get('CidrIpv6', ''), permission))

    return cidrs


def update_security_groups(sg_ids, session):
    ec2 = session.resource('ec2')
    cidrs = []
    sec_groups = []

    atlassian_ips = get_atlassian_ips()

    for sg in sg_ids:
        sec_groups.append(ec2.SecurityGroup(sg))

    for sec_group in sec_groups:
        cidrs += return_all_cidrs_from_sg(sec_group)

    new_ips = [ip for ip in atlassian_ips if ip not in cidrs]
    old_ips = [ip for ip in cidrs if ip not in atlassian_ips]

    for ip in old_ips:
        for sec_group in sec_groups:

            if is_v4(ip):
                ip_permissions = [{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': ip, 'Description': 'Bitbucket cidr'}]}]
            else:
                ip_permissions = [{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'Ipv6Ranges': [{'CidrIpv6': ip, 'Description': 'Bitbucket cidr'}]}]
            try:
                sec_group.revoke_ingress(IpPermissions=ip_permissions)
                print(f"Ip: {ip} has been removed from security group: {sec_group}")

            except ClientError as e:
                if e.response['Error']['Code'] == "RevokeSecurityGroupIngress":
                    print(f"The {ip} is not in this security group: {sec_group}")
                else:
                    print(e)
    print(new_ips)
    for ip in new_ips:
        for sec_group in sec_groups:
            total_number_of_rules = 0
            if is_v4(ip):
                ip_permissions = [{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': ip, 'Description': 'Bitbucket cidr'}]}]

                for perm in list(map(lambda x: x['IpRanges'], sec_group.ip_permissions)):
                    total_number_of_rules += len(list(map(lambda x: x['CidrIp'], perm)))

            else:
                ip_permissions = [{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'Ipv6Ranges': [{'CidrIpv6': ip, 'Description': 'Bitbucket cidr'}]}]

                for perm in list(map(lambda x: x['IpRanges'], sec_group.ip_permissions)):
                    total_number_of_rules += len(list(map(lambda x: x['CidrIp'], perm)))

            if total_number_of_rules < 60:
                req = sec_group.authorize_ingress(IpPermissions=ip_permissions)
                print(req)
                break


def is_v4(ip):
    if ':' in ip:
        return False
    else:
        return True


if __name__ == '__main__':
    vpc_id = "vpc-xxxxxxxxxxxxxx"
    session = boto3.Session(region_name='eu-central-1')
    create_security_groups(session, vpc_id)


