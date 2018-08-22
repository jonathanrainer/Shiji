from setuptools import setup

setup(
    name='shiji_mem_contents',
    version='1.0',
    py_modules=["shiji"],
    url='',
    license='MIT',
    author='Jonathan Rainer',
    author_email='jonathan.rainer@york.ac.uk',
    description='A file to generate memory contents for given benchmark files.',
    install_requires=[
        "Jinja2==2.10",
        "MarkupSafe==1.0",
        "pyeda==0.28.0",
        "pyelftools==0.24",
    ]
)
