#!/usr/bin/env python3

import json
from string import Template
from textwrap import dedent
from datetime import datetime
from dateutil.tz import tzutc

import unittest

import boto3
from botocore.stub import Stubber

# moto 1.3.4 doesn't handle the mocks correctly with:
#   botocore (>= 1.12.8) compatible with latest boto3 (>=1.9.8)
#from moto import mock_ecr, mock_iam

from aws_idem.iam import policy as policy_m

class TestIamActions(unittest.TestCase):

    def policy_document(self, resources=[]):

        policy_template_json = """
            {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "ecr:GetAuthorizationToken",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:GetDownloadUrlForLayer",
                    "ecr:GetRepositoryPolicy",
                    "ecr:DescribeRepositories",
                    "ecr:ListImages",
                    "ecr:DescribeImages",
                    "ecr:BatchGetImage"
                  ],
                  "Resource": [${resources_delimited_string}]
                }
              ]
            }
        """
        # Use Template for substitution
        if not resources:
            resources = ["*"]
        resources_delimited_string = ",".join(['"' + str(x) + '"' for x in resources])

        policy_template_json = dedent(policy_template_json).strip()
        policy_doc_json = Template(policy_template_json)
        policy_doc_json = policy_doc_json.substitute(resources_delimited_string=resources_delimited_string)
        policy_json = json.loads(policy_doc_json)
        return policy_json

    def create_ecr_repo(self):
        account_id = "123456789012"
        region = "us-east-1"
        repository_name = "test_ecr_repo"
        repository_uri = ("{0}.dkr.ecr.{1}.amazonaws.com/{2}"
                          .format(account_id, region , repository_name))
        repository_arn = ("arn:aws:ecr:{0}:{1}:repository/{2}"
                          .format(account_id, region, repository_name))

        expected_create_repository_params = {"repositoryName": repository_name}

        expected_create_repository_response = {
            'repository': {
                            'repositoryArn': repository_arn,
                            'registryId': 'registryId',
                            'repositoryName': repository_name,
                            'repositoryUri': repository_uri,
                            'createdAt': datetime(2015, 1, 1)
                            }
        }
        ecr_client = boto3.client("ecr")
        stubbed_ecr_client = Stubber(ecr_client)

        stubbed_ecr_client.add_response(
            "create_repository",
            service_response=expected_create_repository_response,
            expected_params=expected_create_repository_params)

        with stubbed_ecr_client:
            ecr_response = ecr_client.create_repository(
                repositoryName=repository_name
            )

        return ecr_response

    def stub_list_no_policies(self, stubbed_iam_client=None, policy_name=None, policy_arn=None):

        if not stubbed_iam_client:
            iam_client = boto3.client("iam")
            stubbed_iam_client = Stubber(iam_client)

        if not policy_name:
            policy_name = "test_policy_ecr_ro"

        if not policy_arn:
            policy_arn = 'arn:aws:iam::123456789012:policy/test_policy_ecr_ro'

        expected_list_policies_params = {'Scope': 'Local', 'OnlyAttached': False, 'PathPrefix': '/', 'MaxItems': 100}

        list_policies_response = {
            'Policies': [],
            'IsTruncated': False
        }

        stubbed_iam_client.add_response("list_policies",list_policies_response,expected_list_policies_params)

        return

    def stub_list_policies(self, stubbed_iam_client=None, policy_name=None, policy_arn=None):

        if not stubbed_iam_client:
            iam_client = boto3.client("iam")
            stubbed_iam_client = Stubber(iam_client)

        if not policy_name:
            policy_name = "test_policy_ecr_ro"

        if not policy_arn:
            policy_arn = 'arn:aws:iam::123456789012:policy/test_policy_ecr_ro'

        expected_list_policies_params = {'Scope': 'Local', 'OnlyAttached': False, 'PathPrefix': '/', 'MaxItems': 100}

        list_policies_response = {
            'Policies': [
                {
                    'PolicyName': policy_name,
                    'PolicyId': 'AUFAH9UDH8RZ27SF48LUJ',
                    'Arn': policy_arn,
                    'Path': '/',
                    'DefaultVersionId': 'v1',
                    'AttachmentCount': 0,
                    'CreateDate': datetime(2018, 9, 21, 15, 36, 2, 272131, tzinfo=tzutc()),
                    'UpdateDate': datetime(2018, 9, 21, 15, 36, 2, 272191, tzinfo=tzutc())
                }
            ],
            'IsTruncated': False
        }

        stubbed_iam_client.add_response("list_policies",list_policies_response,expected_list_policies_params)

        return

    def stub_create_policy(self,
                           stubbed_iam_client=None,
                           policy_name=None,
                           policy_arn=None,
                           policy_doc=None):

        if not stubbed_iam_client:
            iam_client = boto3.client("iam")
            stubbed_iam_client = Stubber(iam_client)

        if not policy_name:
            policy_name = "test_policy_ecr_ro"

        if not policy_arn:
            policy_arn = 'arn:aws:iam::123456789012:policy/test_policy_ecr_ro'

        expected_create_policy_params = {
            "PolicyName": policy_name,
            "Path": "/",
            "PolicyDocument":policy_doc,
            "Description":policy_name
        }

        created_policy_response = {
            'Policy': {
                'PolicyName': policy_name,
                'PolicyId': 'AUFAH9UDH8RZ27SF48LUJ',
                'Arn': policy_arn,
                'Path': '/',
                'DefaultVersionId': 'v1',
                'AttachmentCount': 0,
                'CreateDate': datetime(2018, 9, 21, 15, 36, 2, 272131, tzinfo=tzutc()),
                'UpdateDate': datetime(2018, 9, 21, 15, 36, 2, 272191, tzinfo=tzutc())
            }
        }

        stubbed_iam_client.add_response("create_policy",created_policy_response,expected_create_policy_params)

        return

    def test_create_new_policy_no_defaults(self):

        ecr_response = self.create_ecr_repo()
        resources = [ecr_response['repository']['repositoryArn']]
        policy_doc = self.policy_document(resources=resources)
        policy_doc = json.dumps(policy_doc)

        policy_name = "test_policy_ecr_ro"
        policy_arn = 'arn:aws:iam::123456789012:policy/{0}'.format(policy_name)

        iam_client = boto3.client("iam")
        stubbed_iam_client = Stubber(iam_client)

        self.stub_list_no_policies(
            stubbed_iam_client,
            policy_name=policy_name,
            policy_arn=policy_arn)

        self.stub_create_policy(
            stubbed_iam_client,
            policy_name=policy_name,
            policy_arn=policy_arn,
            policy_doc=policy_doc
        )

        with stubbed_iam_client:
            new_policy = policy_m.create_policy(
                client=iam_client,
                policy_name=policy_name,
                policy_document=policy_doc,
                description=policy_name)

            self.assertEqual(new_policy['state'], 'New')
            self.assertEqual(new_policy['policy']['PolicyName'],policy_name)
            self.assertEqual(new_policy['policy']['Arn'],policy_arn)

    def test_create_existing_policy_no_defaults(self):

        ecr_response = self.create_ecr_repo()
        resources = [ecr_response['repository']['repositoryArn']]
        policy_doc = self.policy_document(resources=resources)
        policy_doc = json.dumps(policy_doc)

        policy_name = "test_policy_ecr_ro"
        policy_arn = 'arn:aws:iam::123456789012:policy/{0}'.format(policy_name)

        iam_client = boto3.client("iam")
        stubbed_iam_client = Stubber(iam_client)

        self.stub_list_policies(
            stubbed_iam_client,
            policy_name=policy_name,
            policy_arn=policy_arn)

        self.stub_create_policy(
            stubbed_iam_client,
            policy_name=policy_name,
            policy_arn=policy_arn,
            policy_doc=policy_doc
        )

        with stubbed_iam_client:
            existing_policy = policy_m.create_policy(
                client=iam_client,
                policy_name=policy_name,
                policy_document=policy_doc,
                description=policy_name)

            self.assertEqual(existing_policy['state'], 'Exists')
            self.assertEqual(existing_policy['policy']['PolicyName'],policy_name)
            self.assertEqual(existing_policy['policy']['Arn'],policy_arn)

    def test_delete_existing_policy_by_name(self):

        iam_client = boto3.client("iam")
        stubbed_iam_client = Stubber(iam_client)

        policy_name = "test_policy_ecr_ro"
        policy_arn = 'arn:aws:iam::123456789012:policy/test_policy_ecr_ro'

        list_policies_response = {
            'Policies': [
                {
                    'PolicyName': policy_name,
                    'PolicyId': 'AUFAH9UDH8RZ27SF48LUJ',
                    'Arn': policy_arn,
                    'Path': '/',
                    'DefaultVersionId': 'v1',
                    'AttachmentCount': 0,
                    'CreateDate': datetime(2018, 9, 21, 15, 36, 2, 272131, tzinfo=tzutc()),
                    'UpdateDate': datetime(2018, 9, 21, 15, 36, 2, 272191, tzinfo=tzutc())
                }
            ],
            'IsTruncated': False
        }

        expected_list_policies_params = {'Scope': 'Local', 'OnlyAttached': False, 'PathPrefix': '/', 'MaxItems': 100}

        delete_policy_response = {
            "ResponseMetadata": {}
        }

        expected_delete_policy_params = {
            'PolicyArn': policy_arn
        }

        stubbed_iam_client.add_response("list_policies",list_policies_response,expected_list_policies_params)
        stubbed_iam_client.add_response("delete_policy",delete_policy_response,expected_delete_policy_params)

        with stubbed_iam_client:
            result = policy_m.delete_policy(client=iam_client, policy_name=policy_name)
            self.assertEqual(result['deleted'], True)
            self.assertEqual(result['policy_name'], policy_name)

    def test_delete_existing_policy_by_arn(self):

        iam_client = boto3.client("iam")
        stubbed_iam_client = Stubber(iam_client)

        policy_name = "test_policy_ecr_ro"
        policy_arn = 'arn:aws:iam::123456789012:policy/test_policy_ecr_ro'

        get_policy_response = {
            'Policy': {
                 'PolicyName': policy_name,
                 'PolicyId': 'AUFAH9UDH8RZ27SF48LUJ',
                 'Arn': policy_arn,
                 'Path': '/',
                 'DefaultVersionId': 'v1',
                 'AttachmentCount': 0,
                 'CreateDate': datetime(2018, 9, 21, 15, 36, 2, 272131, tzinfo=tzutc()),
                 'UpdateDate': datetime(2018, 9, 21, 15, 36, 2, 272191, tzinfo=tzutc())
            }
        }

        expected_get_policy_params = {
            'PolicyArn':policy_arn
        }

        delete_policy_response = {
            "ResponseMetadata": {}
        }

        expected_delete_policy_params = {
            'PolicyArn': policy_arn
        }

        stubbed_iam_client.add_response("get_policy",get_policy_response,expected_get_policy_params)
        stubbed_iam_client.add_response("delete_policy",delete_policy_response,expected_delete_policy_params)

        with stubbed_iam_client:
            result = policy_m.delete_policy(client=iam_client,policy_arn=policy_arn)
            self.assertEqual(result['deleted'], True)
            self.assertEqual(result['policy_arn'],policy_arn)

    def test_delete_non_existent_policy_by_name(self):

        iam_client = boto3.client("iam")
        stubbed_iam_client = Stubber(iam_client)

        policy_name = "test_policy_ecr_ro"
        policy_arn = 'arn:aws:iam::123456789012:policy/test_policy_ecr_ro'

        list_policies_response = {
            'Policies': [],
            'IsTruncated': False
        }

        expected_list_policies_params = {'Scope': 'Local', 'OnlyAttached': False, 'PathPrefix': '/', 'MaxItems': 100}

        delete_policy_response = {
            "ResponseMetadata": {}
        }

        expected_delete_policy_params = {
            'PolicyArn': policy_arn
        }

        stubbed_iam_client.add_response("list_policies",list_policies_response,expected_list_policies_params)
        stubbed_iam_client.add_response("delete_policy",delete_policy_response,expected_delete_policy_params)

        with stubbed_iam_client:
            result = policy_m.delete_policy(client=iam_client, policy_name=policy_name)
            self.assertTrue("error" in result)

    def test_delete_non_existent_policy_by_arn(self):

        iam_client = boto3.client("iam")
        stubbed_iam_client = Stubber(iam_client)

        policy_name = "test_policy_ecr_ro"
        policy_arn = 'arn:aws:iam::123456789012:policy/test_policy_ecr_ro'

        delete_policy_response = {
            "ResponseMetadata": {}
        }

        expected_delete_policy_params = {
            'PolicyArn': policy_arn
        }

        stubbed_iam_client.add_client_error("get_policy",
                                            service_error_code="botocore.errorfactory.NoSuchEntityException")
        stubbed_iam_client.add_response("delete_policy",delete_policy_response,expected_delete_policy_params)

        with stubbed_iam_client:
            result = policy_m.delete_policy(client=iam_client,policy_arn=policy_arn)
            self.assertTrue("error" in result)

if __name__ == '__main__':
    unittest.main()


