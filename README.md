# **O r y x**

The Oryx script is a task queuing system with asynchronous multiprocessing for managing Yara scans.

It scans for subdirectories of a given path and inserts them into a queue, meanwhile multiple threads of yara are spawned and fetch paths from the queue to scan. 

Results of the scan are output to results.txt

Logs of the script's activity are written to a local 'logs' directory. 

```
WWWWWWWWWWWWWWWWWWNWW00WWWWMWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWNWWK;lWWNWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWMWWWWWWW
WWWWWWWWWWMWWWWWWNWWd.cNWNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNWWWWWWWWWWWWW
WWWWWWWWWWWWNWM0lldo' 'oddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddocxWWNWWMWWWWW
WWWWWWWWWWWWWWMd,OW0, ,0WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWNc:NWNWMWWWWWW
WWWWWWWWNWWklOWd,OM0' .ckkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkOXMWc:NWNWMWWWWWW
WWWWWWWWWWNl.'do,OMK,                                                              .xMWc:NWNWWWWWWWW
WWWWWWWWWWMO;,:.,OMWl    .'''''''''''''''''''''''''''''''''''''''''''..            .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWo,d:'kWMk.    ............'',;;::::::::::::::::::::::;,'..             .xMWc:NWNWMWWWWWW
WWWWWWWWWNWWX::0o;xNO.     .....'''',,;;;:::::::::::::::::::::;'..                 .xMWc:NWNWMWWWWWW
WWWWWWWWMWNWMO,oXk;ld.     .;::::::::::::::::::::::::::::::;....                   .xMWc:NWNWMWWWWWW
WWWWWWWWMMWNWWk;oX0l'       .',,,,,,,;;;;:::::::::::::::;,.                        .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWWo.:0Xx,        ...''',,;;;:::::::::::::;'.    ....                  .xMWc:NWNWMWWWWWW
WWWWWWWWWWMWNWMd',:kXKd'       .;::::,'''',::::::::::,.                            .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,kd;dKX0o.      .,::'.lOxl,',::::::::;,''...........               .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OWO:c0XX0l.     .':,.lXNXKd,.;;...................                .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMk.'kXXX0o.     .;,';lOXXl...   .....                           .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO. .oKXXX0d,    .,:;.'ld,   .......                            .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OWMO.  .:OXXXXKkc.   .;:,'.                                       .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO. .'''dKXXXXX0d;. .,::;,,,,,'''''''.....                      .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  ,:,.:OXXXXXXX0d;.....................                      .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  ,::;''oKXXXXXXN0,                                          .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO. .,::::;.;kXXXNX0c. ...........                              .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO. .,:::::;''cdxo:.  ....   ..                   ..'',;;;;;;,. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO. .,:::::::;''.   .....  ,;.                   ....'',,;;;:;. .dMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  .',,;::::::'  ....... ;0Oc,.             .',,,,,,,,,;;;:;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  ';;;:::::::;.  ...... .lXNNO'           ':::::::::::::::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO. .,:::::::::::'.   ..... .dNNk.          .;:::::::::::::::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  ';;;;:::::::::;'.  .... 'll'           .::::::::::::::::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  ..'',,,;;:::::::;.   ...   ..          ..''''',,,;;;;:::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO. .,:::::::::::::::::'                     .....''',,,;;;::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  ,::::::::::::::::::,.''''''''......     ':::::::::::::::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  .,,,,,;;;;;;;:::::::::;.............    .';;;;;;;:::::::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.    ........'',,;;;:::::;.  ......          .'',,,,;;;::::;. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd,OMMO.  .,,,,;;;;;;;;;;;;;;;;;;;.   ...           .;;;;;;;;;;;;;,. .xMWc:NWNWMWWWWWW
WWWWWWWWWWWWNWMd;OMMO.                               ..                            .xMWc:NWNWWWWWWWW
WWWWWWWWWWWWNWMd,OMMXdcccccccccccccccccccccccccccccc,..        .;cccccccccccccccccco0MWc:NWNWWWWWWWW
WWWWWWWWWWWWNWMd,OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNo..    .;dKWMMMMMMMMMMMMMMMMMMMMMWc:NWNWMWWWWWW
WWWWWWWWWWWWWWMOcloddoodddddoooddddddddddddddddoooddoo:''..';loodddddddodddddddddoooooo:dWWNWMWWWWWW
WWWWWWWWWWWWWWWWNXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXWWWWWWWWWWWW
WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWMWWWWWWW
```

# Install
This script requires Python 3 (tested with 3.9.5). You will also need to install the requirements included:
> pip3 install -r requirements.txt

# Usage
The yara binary included in this repo was built on MacOS Big Sur; If you're using Linux, you'll need to either copy or symlink your yara binary into this directory or modify the script on line 50 to point to the full path of your yara binary. 

### Usage examples

Using async mode and auto-determining thread count:
> ./oryx.py -r /path/to/rules -p /path/to/directory -m async

Using async mode with 7 threads:
> ./oryx.py -r /path/to/rules -p /path/to/directory -m async -t 7

Pointing to the sample yara rules included:
> ./oryx.py -r sample_rules/Emotet_and_Friends.yara -p /path/to/directory -m async


# Author
Aaron Louks / aaron@zoatrope.com