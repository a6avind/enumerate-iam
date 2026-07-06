from setuptools import setup, find_packages

setup(
    name='enumerate-iam',
    version='1.0.0',
    description='Enumerate the permissions associated with a set of AWS credentials',
    packages=find_packages(),
    include_package_data=True,
    install_requires=['boto3>=1.43.40', 'botocore>=1.43.40'],
    python_requires='>=3.7',
    entry_points={'console_scripts': ['enumerate-iam=enumerate_iam.cli:main']},
)
