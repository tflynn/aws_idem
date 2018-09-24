#!/usr/bin/env python3

import os
from os import path
import json
from string import Template
from textwrap import dedent
from datetime import datetime
from dateutil.tz import tzutc

import unittest
# moto 1.3.4 doesn't handle the mocks correctly with:
#   botocore (>= 1.12.8) compatible with latest boto3 (>=1.9.8)
#from moto import mock_ecr, mock_iam
# Use placebo instead
import placebo

import boto3

from aws_idem.iam import policy as policy_m


PLACEBO_MODE="playback"


def placebo_files_directory():
    full_path = path.realpath(__file__)
    dirname = path.dirname(full_path)
    basename = path.basename(full_path)
    basename_no_ext, ext = path.splitext(basename)
    placebo_dir = path.join(dirname,basename_no_ext + "_placebo")
    if not path.exists(placebo_dir):
        os.mkdir(placebo_dir)
    return placebo_dir


class TestPolicy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        global placebo_files_directory
        global PLACEBO_MODE
        placebo_dir_method = placebo_files_directory
        cls.placebo_dir = placebo_dir_method()
        cls.boto3_session = boto3.Session()
        cls.pill = placebo.attach(cls.boto3_session, data_path=cls.placebo_dir)

        # Pill record/playback have to be called before anything else
        if PLACEBO_MODE == 'record' or os.environ.get('PLACEBO_MODE') == 'record':
            cls.pill.record()
        else:
            cls.pill.playback()


        cls.test_data = {}
        cls.test_data['ecr_repo_data'] = {}
        cls.test_data['ecr_repo_data']['repo_name'] = "test0"
        cls.setup_create_ecr_repo()

        cls.test_data['policy_data'] = {}
        cls.test_data['policy_data']['policy_name'] = "test_policy_ecr_ro"

    @classmethod
    def tearDownClass(cls):
        pass

    @classmethod
    def setup_create_ecr_repo(cls):
        data = cls.test_data['ecr_repo_data']
        # Do it this way so placebo-based testing works
        ecr_client = cls.boto3_session.client("ecr")
        response = ecr_client.create_repository(
            repositoryName=data['repo_name']
        )
        data.update(response['repository'])

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
        #policy_json = json.loads(policy_doc_json)
        return policy_doc_json

    def test_001_create_new_policy_no_defaults(self):

        data = self.test_data['policy_data']
        policy_resources = [self.test_data['ecr_repo_data']['repositoryArn']]
        policy_doc_json = self.policy_document(policy_resources)

        # Do it this way so placebo-based testing works
        iam_client = self.boto3_session.client('iam')

        response = policy_m.create_policy(
            client=iam_client,
            policy_name=data['policy_name'],
            policy_document=policy_doc_json,
            description=data['policy_name'])

        self.assertEqual(response['state'], 'New')
        self.assertEqual(response['policy']['PolicyName'],data['policy_name'])

    def test_002_create_existing_policy_no_defaults(self):

        data = self.test_data['policy_data']
        policy_resources = [self.test_data['ecr_repo_data']['repositoryArn']]
        policy_doc_json = self.policy_document(policy_resources)

        # Do it this way so placebo-based testing works
        iam_client = self.boto3_session.client('iam')

        response = policy_m.create_policy(
            client=iam_client,
            policy_name=data['policy_name'],
            policy_document=policy_doc_json,
            description=data['policy_name'])

        self.assertEqual(response['state'], 'Exists')
        self.assertEqual(response['policy']['PolicyName'],data['policy_name'])

    def test_003_delete_existing_policy_by_name(self):

        data = self.test_data['policy_data']
        policy_name = data['policy_name']

        # Do it this way so placebo-based testing works
        iam_client = self.boto3_session.client('iam')

        response = policy_m.delete_policy(client=iam_client, policy_name=policy_name)
        self.assertEqual(response['deleted'], True)
        self.assertEqual(response['policy_name'], policy_name)

    def test_004_delete_existing_policy_by_arn(self):

        # Have to recreate policy because previous test deleted it
        data = self.test_data['policy_data']

        policy_resources = [self.test_data['ecr_repo_data']['repositoryArn']]
        policy_doc_json_str = self.policy_document(policy_resources)

        # Do it this way so placebo-based testing works
        iam_client = self.boto3_session.client('iam')

        response = policy_m.create_policy(
            client=iam_client,
            policy_name=data['policy_name'],
            policy_document=policy_doc_json_str,
            description=data['policy_name'])

        policy_arn = response['policy']['Arn']

        response = policy_m.delete_policy(client=iam_client,policy_arn=policy_arn)
        self.assertEqual(response['deleted'], True)
        self.assertEqual(response['policy_arn'],policy_arn)

    def test_005_delete_non_existent_policy_by_name(self):

        data = self.test_data['policy_data']
        policy_name = data['policy_name']

        # Do it this way so placebo-based testing works
        iam_client = self.boto3_session.client('iam')

        response = policy_m.delete_policy(client=iam_client, policy_name=policy_name)
        self.assertTrue("error" in response)

    def test_006_delete_non_existent_policy_by_arn(self):

        policy_arn = 'arn:aws:iam::097064421904:policy/test_policy_ecr_ro'

        # Do it this way so placebo-based testing works
        iam_client = self.boto3_session.client('iam')

        response = policy_m.delete_policy(client=iam_client, policy_arn=policy_arn)
        self.assertTrue("error" in response)


if __name__ == '__main__':
    unittest.main()
