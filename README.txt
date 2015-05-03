RUNTIME PREVENTION OF RETURN-ORIENTED PROGRAMMING ATTACKS

ROPGuard is a system for runtime detection and prevention of return-oriented programming (ROP) attacks. It works by defining a set of checks that are performed when certain OS functions are called to determine if those functions are called from the ROP code or as a result of normal program execution. The system can be applied at runtime to any process and has a low CPU and memory overhead. The detailed project documentation can be found in the doc folder.

ROPGuard won the second prize at the Microsoft's BlueHat Prize contest at Black Hat USA 2012 (https://www.microsoft.com/security/bluehatprize/).

The code and other project files provided here are for educational purposes only. If you are interested in running ROPGuard to protect your computer, I recommend you download Microsoft EMET instead (http://www.microsoft.com/emet), as it implements protection mechanisms from ROPGuard (see: http://www.microsoft.com/en-us/news/Press/2012/Jul12/07-25BlueHatPrizePR.aspx), but also contains many reliability improvements and is actively maintained. I'd like to thank Elias Bachaalany of Microsoft for not only implementing ROPGuard technology into EMET but also improving it in every way.

.\doc folder contains the documentation in .doc and .pdf format

.\bin folders contains all executables and other files needed to run the prototype. Prototype usage is described in the documentation.

.\ropguard, .\ropguarddll and .\common folders contain all the source and project files of the prototype

.\vulnapp folder contains the source and the project files of an example vulnerable application used during the evaluation
