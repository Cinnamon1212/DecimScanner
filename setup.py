from setuptools import setup
from setuptools import find_packages

setup(name="DecimScanner",
      version="1.0",
      description="A threaded scanner package for python",
      author="Cinnamon1212",
      url="https://github.com/Cinnamon1212/",
      install_requires=['scapy'],
      packages=find_packages(),
      keywords=["python", "threaded scanners", "TCP", "UDP", "ICMP", "Penetration testing", "pentesting", "scapy"],
      classifiers=[
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          "Operating System :: Unix"
      ]
)
