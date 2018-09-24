# aws_idem

Lightweight implementations of subsets of some AWS Boto3 features.

This toolset is mostly intended for tools that support 
system configuration and management.

All calls can be rerun multiple times without harm. 

Typically, the first call actually affects the applicable resource. 
Second and subsequent calls have no effect, but should return much the same data
as the original call. 
 
In the cases where this is not practical, this is noted. e.g:
* Deletion of KMS keys since deletion is not immediate.

## Installation

`pip3 install .`

## Usage

```
from aws_idem.iam import policy

policy.create_policy(policy_name, policy_document, description)
policy.list_policies_by_name(name_regex)
policy.delete_policy(policy_name)
policy.delete_policy(policy_arn)
```


## Testing

Testing uses [placebo](https://github.com/garnaat/placebo) 
to record and later playback boto3 call output.

The source code (this repo) is required for testing. 

The easiest way to run the tests is using 'nose' at the root of the code tree.

`nosetests`

### To add new tests

*placebo* records calls actual call to boto3 in sequence. So, if tests are added:

* Name them so they fall in the correct sequence - e.g. test\_\<nnn\>\_...
* Delete applicable AWS resources
* Delete the applicable '\_placebo' subdirectory
* Either:
    * Set the environment variable 'PLACEBO_MODE' to 'record'
* Or:
    * Change the value for 'PLACEBO_MODE' to 'record' towards the top of the test file
* Run all the tests once to collect the placebo output
* Either:
    * Set the environment variable 'PLACEBO_MODE' to  'playback' or clear it.
* Or:
    * Change the value for 'PLACEBO_MODE' to 'playback' towards the top of the test file
* Delete applicable AWS resources



