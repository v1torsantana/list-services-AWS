import boto3
import botocore.exceptions

def handle_errors(service_name, region, func):
    """Executa a função do serviço e captura erros de permissão."""
    try:
        return func()
    except botocore.exceptions.ClientError as e:
        error_message = str(e)
        if "AccessDenied" in error_message or "UnauthorizedOperation" in error_message:
            return []  # Retorna lista vazia para ignorar completamente a região sem permissão
        else:
            print(f"Erro inesperado em {region}: {e}")  # Mostra erros não relacionados a permissão
            return []

def get_ec2_instances(session, region):
    return handle_errors("EC2", region, lambda: [
        [
            "EC2",
            region,
            f"{next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'Sem Nome')} ({instance.get('PrivateIpAddress', 'Sem IP')})"
        ]
        for reservation in session.client("ec2", region_name=region).describe_instances()["Reservations"]
        for instance in reservation["Instances"]
        if instance.get("State", {}).get("Name") != "stopped"
    ])


def get_elb_load_balancers(session, region):
    return handle_errors("Load Balancer", region, lambda: [
        ["Load Balancer", region, lb["LoadBalancerName"]]
        for lb in session.client("elbv2", region_name=region).describe_load_balancers()["LoadBalancers"]
    ])

def get_rds_instances(session, region):
    return handle_errors("RDS", region, lambda: [
        ["RDS", region, db["DBInstanceIdentifier"]]
        for db in session.client("rds", region_name=region).describe_db_instances()["DBInstances"]
    ])

def get_dynamodb_tables(session, region):
    return handle_errors("DynamoDB", region, lambda: [
        ["DynamoDB", region, table]
        for table in session.client("dynamodb", region_name=region).list_tables()["TableNames"]
    ])

def get_lambda_functions(session, region):
    return handle_errors("Lambda", region, lambda: [
        ["Lambda", region, func["FunctionName"]]
        for func in session.client("lambda", region_name=region).list_functions()["Functions"]
    ])

def get_api_gateways(session, region):
    return handle_errors("API Gateway", region, lambda: [
        ["API Gateway", region, api["name"]]
        for api in session.client("apigateway", region_name=region).get_rest_apis()["items"]
    ])

def get_mq_brokers(session, region):
    return handle_errors("Amazon MQ", region, lambda: [
        ["Amazon MQ", region, broker["BrokerName"]]
        for broker in session.client("mq", region_name=region).list_brokers()["BrokerSummaries"]
    ])

def get_route53_domains(session):
    """Route 53 é global, então não precisa iterar regiões"""
    return handle_errors("Route 53", "Global", lambda: [
        ["Route 53", "Global", zone["Name"]]
        for zone in session.client("route53").list_hosted_zones()["HostedZones"]
    ])

def get_ebs_volumes(session, region):
    return handle_errors("EBS", region, lambda: [
        ["EBS", region, f"{volume['VolumeId']} ({volume['State']}, {volume['VolumeType']})"]
        for volume in session.client("ec2", region_name=region).describe_volumes()["Volumes"]
    ])

def get_lightsail_instances(session, region):
    return handle_errors("Lightsail", region, lambda: [
        ["Lightsail", region, instance["name"]]
        for instance in session.client("lightsail", region_name=region).get_instances()["instances"]
    ])

def get_nacls(session, region):
    return handle_errors("NACLs", region, lambda: [
        ["NACL", region, nacl["NetworkAclId"]]
        for nacl in session.client("ec2", region_name=region).describe_network_acls()["NetworkAcls"]
    ])

def get_security_groups(session, region):
    return handle_errors("SecurityGroups", region, lambda: [
        ["SecurityGroup", region, sg["GroupId"]]
        for sg in session.client("ec2", region_name=region).describe_security_groups()["SecurityGroups"]
    ])

def get_internet_gateways(session, region):
    return handle_errors("InternetGateways", region, lambda: [
        ["InternetGateway", region, igw["InternetGatewayId"]]
        for igw in session.client("ec2", region_name=region).describe_internet_gateways()["InternetGateways"]
    ])

def get_elastic_ips(session, region):
    return handle_errors("ElasticIPs", region, lambda: [
        ["ElasticIP", region, address.get("AllocationId", address.get("PublicIp"))]
        for address in session.client("ec2", region_name=region).describe_addresses()["Addresses"]
    ])

def get_target_groups(session, region):
    return handle_errors("TargetGroups", region, lambda: [
        ["TargetGroup", region, tg["TargetGroupArn"]]
        for tg in session.client("elbv2", region_name=region).describe_target_groups()["TargetGroups"]
    ])

def get_firewall_policies(session, region):
    return handle_errors("FirewallPolicies", region, lambda: [
        ["FirewallPolicy", region, policy["FirewallPolicyId"]]
        for policy in session.client("network-firewall", region_name=region).list_firewall_policies()["FirewallPolicies"]
    ])

def get_vpc_endpoints(session, region):
    return handle_errors("VPCEndpoints", region, lambda: [
        ["VPCEndpoint", region, ep["VpcEndpointId"]]
        for ep in session.client("ec2", region_name=region).describe_vpc_endpoints()["VpcEndpoints"]
    ])

def get_transit_gateways(session, region):
    return handle_errors("TransitGateways", region, lambda: [
        ["TransitGateway", region, tg["TransitGatewayId"]]
        for tg in session.client("ec2", region_name=region).describe_transit_gateways()["TransitGateways"]
    ])


def run_service(service_function, session, regions):
    all_services = []
    for region in regions:
        print(f"🔎 Verificando {region}...")  # Debug: saber quais regiões estão sendo processadas
        result = service_function(session, region)

        if result:
            all_services.extend(result)  # Adiciona apenas se houver resultados válidos

    # Exibir resultados somente se houver serviços encontrados
    if all_services:
        print("\nResultados:\n")
        print(f"{'Serviço':<20} {'Região':<15} {'Nome'}")
        print("=" * 50)
        for service, region, name in all_services:
            print(f"{service:<20}\t{region:<15}\t{name}")
    else:
        print("🚨 Nenhum serviço encontrado. Verifique as permissões e credenciais.")
def get_route_tables(session, region):
    return handle_errors("RouteTables", region, lambda: [
        ["RouteTable", region, rt["RouteTableId"]]
        for rt in session.client("ec2", region_name=region).describe_route_tables()["RouteTables"]
    ])

def get_nat_gateways(session, region):
    return handle_errors("NATGateways", region, lambda: [
        ["NATGateway", region, nat["NatGatewayId"]]
        for nat in session.client("ec2", region_name=region).describe_nat_gateways()["NatGateways"]
    ])

def get_vpc_peerings(session, region):
    return handle_errors("VPCPeeringConnections", region, lambda: [
        ["VPCPeering", region, pcx["VpcPeeringConnectionId"]]
        for pcx in session.client("ec2", region_name=region).describe_vpc_peering_connections()["VpcPeeringConnections"]
    ])

def get_vpcs(session, region):
    return handle_errors("VPCs", region, lambda: [
        ["VPC", region, vpc["VpcId"]]
        for vpc in session.client("ec2", region_name=region).describe_vpcs()["Vpcs"]
    ])

def get_subnets(session, region):
    return handle_errors("Subnets", region, lambda: [
        ["Subnet", region, subnet["SubnetId"]]
        for subnet in session.client("ec2", region_name=region).describe_subnets()["Subnets"]
    ])

def get_network_interfaces(session, region):
    return handle_errors("NetworkInterfaces", region, lambda: [
        ["ENI", region, eni["NetworkInterfaceId"]]
        for eni in session.client("ec2", region_name=region).describe_network_interfaces()["NetworkInterfaces"]
    ])

def get_classic_load_balancers(session, region):
    return handle_errors("ClassicLoadBalancers", region, lambda: [
        ["CLB", region, lb["LoadBalancerName"]]
        for lb in session.client("elb", region_name=region).describe_load_balancers()["LoadBalancerDescriptions"]
    ])

def get_albs(session, region):
    return handle_errors("ALBs", region, lambda: [
        ["ALB", region, lb["LoadBalancerArn"]]
        for lb in session.client("elbv2", region_name=region).describe_load_balancers()["LoadBalancers"]
        if lb["Type"] == "application"
    ])

def get_nlbs(session, region):
    return handle_errors("NLBs", region, lambda: [
        ["NLB", region, lb["LoadBalancerArn"]]
        for lb in session.client("elbv2", region_name=region).describe_load_balancers()["LoadBalancers"]
        if lb["Type"] == "network"
    ])

def get_firewalls(session, region):
    return handle_errors("NetworkFirewalls", region, lambda: [
        ["Firewall", region, fw["FirewallName"]]
        for fw in session.client("network-firewall", region_name=region).list_firewalls()["Firewalls"]
    ])


def get_vpc_flow_logs(session, region):
    return handle_errors("VPCFlowLogs", region, lambda: [
        ["FlowLog", region, log["FlowLogId"]]
        for log in session.client("ec2", region_name=region).describe_flow_logs()["FlowLogs"]
    ])

def get_iam_policies(session, region):
    # IAM é global, region é ignorado mas mantido no padrão
    return handle_errors("IAMPolicies", region, lambda: [
        ["IAMPolicy", region, policy["PolicyName"]]
        for policy in session.client("iam").list_policies(Scope='Local')['Policies']
    ])

def get_iam_roles(session, region):
    # IAM é global, region ignorado mas mantido para padrão
    return handle_errors("IAMRoles", region, lambda: [
        ["IAMRole", region, role["RoleName"]]
        for role in session.client("iam").list_roles()['Roles']
    ])

regions = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "sa-east-1"
]


session = boto3.Session(
    # aws_access_key_id="",
    # aws_secret_access_key="",
    # aws_session_token=""
)

# Exemplo de uso: rodar apenas Lambda
run_service(get_ec2_instances, session, regions)