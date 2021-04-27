import pathlib
from setuptools import setup
from setuptools import find_packages

README = (pathlib.Path(__file__).parent / "README.md").read_text()

setup(name="DecimScanner",
      version="1.4.2",
      long_description=README,
      long_description_content_type="text/markdown",
      description="A threaded scanner package for python",
      author="Cinnamon1212",
      url="https://github.com/Cinnamon1212/",
      install_requires=['scapy', 'pybluez', 'bs4', 'dnspython'],
      packages=find_packages(where="src"),
      keywords=["python", "threaded scanners", "TCP", "UDP", "ICMP", "Penetration testing", "pentesting", "scapy"],
      classifiers=[
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          "Operating System :: Unix"
      ],
      package_dir={"": "src"},
      entry_points={
        "console_scripts": ["DecimScanner=DecimScanner.__main__:main"]
      }
)
