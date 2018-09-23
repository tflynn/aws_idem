from setuptools import setup, find_packages
import setuptools.command.test

setup(name='aws_idem',
      version='0.1',
      description='AWS idempotent wrappers for some boto3 calls',
      url='https://github.com/tflynn/aws_idem.git',
      author='Tracy Flynn',
      author_email='tracysflynn@gmail.com',
      license='MIT',
      packages=find_packages(),
      install_requires=['boto3','placebo'],
      test_suite='nose.collector',
      tests_require=['nose'],
      zip_safe=False)
