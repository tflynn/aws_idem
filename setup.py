from setuptools import setup, find_packages
import setuptools.command.test

class TestCommand(setuptools.command.test.test):
    """ Setuptools test command explicitly using test discovery. """

    def _test_args(self):
        yield 'discover'
        for arg in super(TestCommand, self)._test_args():
            yield arg


setup(name='aws_idem',
      version='0.1',
      description='AWS  idempotent wrappers for some boto3 calls',
      url='https://github.com/tflynn/aws_idem.git',
      author='Tracy Flynn',
      author_email='tracysflynn@gmail.com',
      license='MIT',
      packages=find_packages(),
      install_requires=['boto3','placebo'],
      test_suite='nose.collector',
      tests_require=['nose'],
      # cmdclass={
      #     'test': TestCommand,
      # },
      zip_safe=False)
