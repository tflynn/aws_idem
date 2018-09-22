# aws_idem

Lightweight implementations of subsets of some AWS Boto3 features.

This toolset is mostly intended for tools that support 
system configuration and management.

All calls are idempotent except as explicitly noted or in
cases where it is impractical. e.g:
* Deletion of KMS keys since deletion is not immediate.


## Installation

`pip3 install .`

## Usage

`from aws_idem.iam import policy`

## AWS IAM

### Policies

