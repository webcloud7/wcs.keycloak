import os

from setuptools import find_packages, setup

long_description = "\n\n".join(
    [
        open("README.md").read(),
        open(os.path.join("docs", "HISTORY.txt")).read(),
    ]
)

tests_require = [
    "plone.app.testing",
    "plone.testing",
    "plone.api",
    "zope.testrunner",
    "requests",
    "beautifulsoup4",
]

setup(
    name="wcs.keycloak",
    version="1.0.0a1.dev0",
    description="Keycloak integration for Plone",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Environment :: Web Environment",
        "Framework :: Plone",
        "Framework :: Plone :: 6.0",
        "Framework :: Plone :: Addon",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.11",
        "Development Status :: 3 - Alpha",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    ],
    keywords="Plone Usermanagement Groupmanagement Keycloak PAS",
    author="Mathias Leimgruber",
    author_email="m.leimgruber@webcloud7.ch",
    url="https://pypi.python.org/pypi/wcs.keycloak",
    license="GPL version 2",
    packages=find_packages(exclude=["ez_setup"]),
    namespace_packages=["wcs"],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        "python-keycloak",
        "Plone",
        "plone.autoinclude",
        "plone.restapi",
        "setuptools",
    ],
    extras_require=dict(
        test=tests_require,
        tests=tests_require,
    ),
    entry_points="""
    # -*- Entry points: -*-
    [plone.autoinclude.plugin]
    target = plone
    """,
)
