from setuptools import setup

setup(
    name='swport',
    version='1.0',
    py_modules=['swport'],
    entry_points={
        'console_scripts': [
            'swport=swport:main',
        ],
    },
    author='Samurai_vxtW',
    description='Advanced port scanner built in Python, inspired by Nmap.',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent'
    ],
    python_requires='>=3.6',
)
