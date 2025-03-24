terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.0.0"
    }
  }
  backend "remote" {
    backend "s3" {
    bucket         = "your-terraform-state-bucket"  # S3 버킷 이름
    key            = "path/to/terraform.tfstate"      # state 파일 경로
    region         = "us-east-1"                      # 버킷 리전
    encrypt        = true                             # state 파일 암호화 여부
    dynamodb_table = "your-terraform-lock-table"      # 미리 생성한 DynamoDB 테이블 이름
    use_lockfile   = true
  }
}

#########################
# Provider & Variables  #
#########################

provider "aws" {
  region = var.region
}

# Kubernetes provider는 EKS 클러스터 정보로 동적 설정됩니다.
data "aws_eks_cluster" "eks_cluster" {
  name = var.cluster_name
}

data "aws_eks_cluster_auth" "cluster" {
  name = var.cluster_name
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.eks_cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks_cluster.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.cluster.token
}

#####################
# VPC & Networking  #
#####################

resource "aws_vpc" "eks_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "eks-vpc"
  }
}

resource "aws_internet_gateway" "eks_igw" {
  vpc_id = aws_vpc.eks_vpc.id
  tags = {
    Name = "eks-igw"
  }
}

resource "aws_subnet" "eks_subnets" {
  count                   = length(var.azs)
  vpc_id                  = aws_vpc.eks_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.azs[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = "eks-subnet-${count.index}"
  }
}

resource "aws_route_table" "eks_route_table" {
  vpc_id = aws_vpc.eks_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.eks_igw.id
  }

  tags = {
    Name = "eks-route-table"
  }
}

resource "aws_route_table_association" "eks_rta" {
  count          = length(aws_subnet.eks_subnets)
  subnet_id      = aws_subnet.eks_subnets[count.index].id
  route_table_id = aws_route_table.eks_route_table.id
}

###############################
# IAM Roles & Policies for EKS#
###############################

# EKS 클러스터 역할
resource "aws_iam_role" "eks_cluster_role" {
  name = "eks_cluster_role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# EKS 워커(Node) 역할
resource "aws_iam_role" "eks_node_role" {
  name = "eks_node_role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSCNIPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_registry_policy" {
  role       = aws_iam_role.eks_node_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

##########################
# EKS Cluster & NodeGroup#
##########################

resource "aws_eks_cluster" "eks_cluster" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids = aws_subnet.eks_subnets[*].id
  }

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
}

resource "aws_eks_node_group" "eks_node_group" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = var.node_group_name
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = aws_subnet.eks_subnets[*].id

  scaling_config {
    desired_size = var.desired_capacity
    max_size     = var.max_capacity
    min_size     = var.min_capacity
  }

  update_config {
    max_unavailable = 1
  }

  # Node Group 업그레이드시 새 리소스를 생성한 후 기존 노드를 제거하여 서비스 중단을 최소화합니다.
  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.eks_registry_policy,
  ]
}

############################
# Kubernetes 리소스 (nginx) #
############################

# nginx용 네임스페이스 생성
resource "kubernetes_namespace" "nginx_ns" {
  metadata {
    name = "nginx"
  }
}

# nginx Deployment (replica 3개로 고가용성 구성)
resource "kubernetes_deployment" "nginx_deployment" {
  metadata {
    name      = "nginx"
    namespace = kubernetes_namespace.nginx_ns.metadata[0].name
    labels = {
      app = "nginx"
    }
  }

  spec {
    replicas = 3

    selector {
      match_labels = {
        app = "nginx"
      }
    }

    template {
      metadata {
        labels = {
          app = "nginx"
        }
      }

      spec {
        container {
          name  = "nginx"
          image = "nginx:latest"
          ports {
            container_port = 80
          }
        }
      }
    }
  }
}

# AWS LoadBalancer에 연결할 보안 그룹 (오직 123.123.123.123/32만 허용)
resource "aws_security_group" "lb_sg" {
  name        = "nginx-lb-sg"
  description = "Allow access only from specific IP"
  vpc_id      = aws_vpc.eks_vpc.id

  ingress {
    description = "Allow nginx access from specific IP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["123.123.123.123/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# nginx Service (LoadBalancer 타입, 보안 그룹 지정)
resource "kubernetes_service" "nginx_service" {
  metadata {
    name      = "nginx-service"
    namespace = kubernetes_namespace.nginx_ns.metadata[0].name
    annotations = {
      # AWS LB에 직접 보안 그룹을 지정하여 외부 접속 IP를 제한합니다.
      "service.beta.kubernetes.io/aws-load-balancer-security-groups" = aws_security_group.lb_sg.id
      "service.beta.kubernetes.io/aws-load-balancer-internal"            = "false"
    }
  }

  spec {
    selector = {
      app = "nginx"
    }
    port {
      port        = 80
      target_port = 80
    }
    type = "LoadBalancer"
  }
}

# Ingress 리소스 (nginx.example.com 도메인, 오직 123.123.123.123/32에서의 접근 허용)
# 단, 실제 Ingress Controller(예: nginx ingress controller)는 별도 설치되어 있어야 합니다.
resource "kubernetes_ingress" "nginx_ingress" {
  metadata {
    name      = "nginx-ingress"
    namespace = kubernetes_namespace.nginx_ns.metadata[0].name
    annotations = {
      "kubernetes.io/ingress.class"                          = "nginx"
      "nginx.ingress.kubernetes.io/whitelist-source-range"     = "123.123.123.123/32"
    }
  }
  spec {
    rule {
      host = "nginx.example.com"
      http {
        path {
          path = "/"
          backend {
            service_name = kubernetes_service.nginx_service.metadata[0].name
            service_port = 80
          }
        }
      }
    }
  }
}
