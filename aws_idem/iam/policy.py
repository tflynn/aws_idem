import boto3
import re
import traceback
import json


MAX_ITEMS = 100


def delete_policy(
        client=None,
        policy_name=None,
        policy_arn=None,
        path=None):

    """
    Delete a policy specified by name or ARN. This will fail if the policy has any attachments

    Args:
        client (obj): boto3 client
        policy_name (str): Policy name. One and only one of policy name or policy ARN must be given.
        policy_arn (str): Policy ARN.
        path (str): Policy path

    Returns:
        Success (dict):
            return {"deleted":True, "policy_name":policy_name, "policy_arn":policy_arn}
        Failure (dict):
            {"error" : str(Error text) }

    """

    try:
        if not client:
            client = boto3.client('iam')

        if not policy_name and not policy_arn:
            return {"error": "delete_policy: Either policy name or policy ARN must be specified"}

        if not path:
            path = "/"

        if policy_name:
            response = list_policies_by_name(
                client=client,
                name_regex=('.*' + policy_name + '.*'),
                scope='Local',
                path_prefix=path
            )
            if 'error' in response:
                return response['error']
            else:
                policies = response['policies']
                # Pick first matching policy if multiple match
                if policies:
                    policy = policies[0]
                else:
                    policy = None

        else:
            response = client.get_policy(
                PolicyArn=policy_arn
            )
            if 'Policy' in response:
                policy = response['Policy']
            else:
                policy = None

        if policy and policy['AttachmentCount'] > 0:
            return {"error": ("delete_policy: Policy {0} has attachments. Cannot delete"
                              .format(policy['PolicyName']))}

        if policy:
            client.delete_policy(
                PolicyArn=policy['Arn']
            )
            return {"deleted": True, "policy_name": policy_name, "policy_arn": policy_arn}
        else:
            return {"error": ("delete_policy: policy {0} does not exist. Cannot delete"
                              .format(policy_name))}

    except Exception as e:
        return {"error": "delete_policy Error {0} {1}".format(e, traceback.format_exc())}


def create_policy(
        client=None,
        policy_name=None,
        path=None,
        policy_document=None,
        description=None):
    """
    Create an IAM policy

    Args:
        client (obj): boto3 client
        policy_name (str): Policy name
        path (str): Policy path
        policy_document (str): JSON policy document
        description (str): Policy description. Defaults to 'name'

    Returns:
        Success (dict):
            {
                "policy" (dict): Policy information (see boto3.create_policy),
                "state" (str): "New" | "Exists"
            }

        Failure (dict):
            {"error" : str(Error text) }

    """

    try:
        if not client:
            client = boto3.client('iam')

        if not description:
            description = policy_name

        if not path:
            path = "/"

        if not isinstance(policy_document,str):
            policy_document = json.dumps(policy_document)

        if policy_name:
            response = list_policies_by_name(
                client=client,
                name_regex=('.*' + policy_name + '.*'),
                scope='Local',
                path_prefix=path
            )
            if 'error' in response:
                return response['error']
            else:
                policies = response['policies']
                # Pick first matching policy if multiple match
                if policies:
                    policy = policies[0]
                    return {'policy': policy, 'state':'Exists'}

        response = client.create_policy(
            PolicyName=policy_name,
            Path=path,
            PolicyDocument=policy_document,
            Description=description
        )
        if 'Policy' in response:
            return {'policy' : response['Policy'], 'state':'New'}
        else:
            return {"error" : "create_policy boto3.create_policy bad return {0}".format(response)}

    except Exception as e:
        return {"error": "create_policy Error {0} {1}".format(e, traceback.format_exc())}


def list_policies_by_name(
        client=None,
        name_regex=None,
        scope='Local',
        path_prefix='/',
        marker=None,
        max_items=MAX_ITEMS):

    """
    List all policies matching a given name (fragment)

    Args:
        client (obj): boto3 client
        name_regex (str): String containing a regex to test for the policy name
        scope (str): Scope 'All' | 'AWS' | 'Local'. Defaults to 'Local'
        path_prefix (str): Policy path. Defaults to '/'.
        marker (str): Pagination marker. Defaults to 'None'.
        max_items (int): Max items in any one (paginated) call. Defaults to 100.

    Returns:
        Success (dict): {"policies" : list(dict) }
            Each dict entry contains policy info. See boto3.list_policies

        Failure (dict):
            {"error" : str(Error text) }
    """

    try:
        if not client:
            client = boto3.client('iam')

        if not name_regex:
            return {"error": "Invalid argument. No name regex specified."}

        name_regex = re.compile(name_regex)

        kwargs = dict(
            Scope=scope,
            OnlyAttached=False,
            PathPrefix=path_prefix,
            MaxItems=max_items
        )
        if marker:
            kwargs.update(dict(Marker=marker))

        response = client.list_policies(**kwargs)

        all_policies = []

        if 'Policies' in response:
            matching_policies = [policy for policy in response['Policies'] if name_regex.match(policy['PolicyName'])]
            all_policies.extend(matching_policies)

        if response['IsTruncated']:
            kwargs = dict(
                client=client,
                name_regex=name_regex,
                scope=scope,
                path_prefix = path_prefix,
                max_items=max_items
            )
            if marker:
                kwargs.update(dict(marker=marker))
            matching_policies = list_policies_by_name(**kwargs)
            all_policies.extend(matching_policies)

        return {"policies": all_policies}

    except Exception as e:
        return {"error": "Error {0} {1}".format(e, traceback.format_exc())}
