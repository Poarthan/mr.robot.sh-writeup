# [mr.robot.sh](https://tirefire.org/posts/fedora-practice/) Writeup

## The challenge: 
The image is linked here: [https://tirefire.org/posts/fedora-practice/](https://tirefire.org/posts/fedora-practice/)

mr.robot.sh is a Fedora practice image created by tirefire, to help students learn about various techniques and how to find them. Therefore there are forensics questions tied to each vulnerability in the image.

### Scenario:

It is company policy to use only Fedora 36 on this computer. It is also company policy to use only the latest, official, stable Fedora 36 packages available for required software and services on this computer. Management has decided that the default web browser for all users on this computer should be the latest stable version of Firefox. Company policy is to never let users log in as root. If administrators need to run commands as root, they are required to use the "sudo" command.

E Corp Workstation

You're an All Safe Employee given this user's workstation to perform forensics and secure it to return it to the user. This is a desktop for Fred. Fred is the only authorized user for this system. Firefox is the only authorized software. All employee duties can be performed in the web browser. Ensure that there are no other services running and that the firewall doesn't allow any remote access.

## Solving:
To start, when you open terminal you are in an rbash(restricted bash) shell where many useful commands don't work. After a bit of googling, we find that the method that works for changing the shell is just `bash` and we enter a normal bash shell. From here on, you should start by solving all the **forensics questions first** before looking to gaining any other points, but the writeup will be written in a format where below each forensic will be the vulnerabilities linked to that forensic. 

### Firefox installed
This vuln comes with the virtual machine therefore it is a free vulnerability and you will get points for it no matter what.

### Removed restricted bash installed from fedorarepo
The restricted bash is obviously something unnecessary and should thus be deleted. You will score points just by deleting the rbash binary. You can find it with `sudo find / -iname *rbash* 2>/dev/null`

### Fixing DNF repository: Removed fedorarepo yum repository
So if you try to install anything you will find that it doesn't work. So to fix this you go to /etc/yum.repos.d/ and delete all the unnecesary/unusual files, you can figure this out by comparing it to a normal /etc/yum.repos.d and looking for differences.

### Firewall not allowing external connections and Disabled ssh inbound firewall rule
In the README it says to ensure that 'the firewall doesn't allow any remote access' so this is a clue that there are firewall vulnerabilities. These might be somewhat tricky for those who haven't used the Fedora firewall before, because if one follows the fedora docs page, you will be told to use `sudo firewall-cmd --list-all`, but that just lists the firewall rules in the default/public zone, which wasn't where the malicious rules were added to. You also would have a hard time finding these rules with a GUI client like firewall-config. 
To find the malicious rules you run `sudo firewall-cmd --list-all-zones` and it will list all for all the zones on the system. You can find out what all the zones are with `sudo firewall-cmd --get-zones`. 
After looking through all the zones you will find that there are some extra unnecessary rules added to the external zone, you can check this with `sudo firewall-cmd --zone=external --list-all`, so to remove these you run `sudo firewall-cmd --zone=external --remove-port=4444/tcp --permanent` and ` sudo firewall-cmd --zone=external --remove-service=ssh --permanent`

### Forensics 1:
```
SSH keys are sensitive information and should be protected. They're usually 
found in a users home directory under a subdirectory called .ssh. These should 
be protected by file permissions restricting access only to the user. 
Additionally, authorized_keys is a file that contains public keys that are 
authorized to log in as a user. This file should also be protected so that an 
attacker can't add their own public key. What is the uid of the owner of fred's 
ssh private key?
ANSWER: 65534
```
SSH keys are usually stored in `~/.ssh`, so we look and we find them in there, with `ls -al` we can see that the owner is the user nobody. Running `id -u nobody`, we get 65534.

### SSH authorized keys and private keys are not world readable/writable
The SSH keys are linked to another vuln, so fixing the permissions making the private key permissions 600 and the public key permissions 644 and both owned by Fred gains points.

### Forensics 2:
```
Fred has installed another web browser in attempt to use it for remote access. 
What is the fedora package name for this other browser that's installed?
ANSWER: chromium.x86_64
```
For this one I ran `sudo dnf list installed` and looked through the installed packages for anything that was a web browser, and so this chromium package was found.

### Removed Chromium broser
So obviously from reading the readme this package is unnecessary, therefore, you should uninstall the chromium browser with `sudo dnf remove chromium`.

### Forensics 3:
```
An Elasticsearch and Kibana frontend have been installed on this host. This is 
also called an ELK stack with combined with Logstash. There is a dashboard set 
up for the elastic user. What is the title of the dashboard?
ANSWER: Red Wheelbarrow
```
If you just open the website to the local server, you will find that it is called Red Wheelbarrow.

### Removed kibana service and Removed elasticsearch service
Again the ELK stack is unnecessary therefore you should stop the kibana and elasticsearch services by finding their pids with `ps aux | grep kibana` and `px aux | grep elastic` and killing them `sudo kill -9 <pid>` then dnf remove the files.

### Forensics 4:
```
We've had detections of compromised binaries that are backdoored to call out to 
the host ifconfig.me. These binaries are present on this host, what are the 
md5sums of these binaries so that we can use them as Indicators of Compromise 
(IOCs) to share out to the community so that others might also detect when 
they're compromised.

ANSWER: 64aa52cfd258963b2398650fa27f43ba
ANSWER: f64577379f87f0df920ee59397de08b2
```
Inside /bin, where binaries are generally stored I ran `grep -rnw . -e ifconfig.me` and grep will also look for binaries with matches. The results were sudoreplay, curl, wget and sudo. So the answer's should be wget and curl, therefore we can md5sum these 2 to score.

### Removed backdoored curl and Removed backdoored wget
Since these 2 binaries obviously have problems, we need to fix them and the easiest way to do that is to reinstall them with: `sudo dnf reinstall curl` and `sudo dnf reinstall wget`

### Forensics 5:
```
One of the users on this system is using a non-standard shell that isn't found 
in /etc/shells. Which user is it?
ANSWER: /sbin/login
```
All the users and their shells are in /etc/shells. Fred has a normal shell, so it has to be one of the system/service users which most should have a shell like /sbin/nologin or /bin/false. So if we `cat /etc/passwd | grep -v nologin` we filter out most of the normal shells. We see that /sbin/login is the most suspicious of all of them and if you google, you will find the rest of the shells to be default shells for those users.

### Removed systemd-root user
The user with the shell /sbin/login is the systemd-root user so the obvious next step is to remove that user. You can't just delete the line from /etc/passwd, at least that didn't work for me, but `sudo userdel -f systemd-root` worked, the -f option means forcefully as it is being used by another process or something

### Forensics 6:
```
Docker was found hosting a service on this system. What is the name of the 
docker container that's running?
ANSWER: fedorarepo
```
The first thing I tried was `ps aux | grep docker`, but there was no container name for that. After doing some quick googling we find the command `docker ps --all` and that lists the container name.

### Removed docker
So this docker container should be removed, again similar to removing kibana and elasticsearch, stop the process and then remove all docker related packages:
```
sudo dnf remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-selinux \
                  docker-engine-selinux \
                  docker-engine
```

### Forensics 7:
```
Fred has been detected using remote access software that allows him to log in 
from home. This software is not authorized. What is the name of the remote 
access software that Fred is using?
ANSWER: gnome-remote-desktop
```
This one took a lot of looking around, eventually I found that inside the gnome desktop settings, in the sharing section there was a suspicious remote desktop and after doing some research, I found that this was Gnome's Remote desktop.

### Removed gnome-remote-desktop
This first one is easy, this remote desktop software is unauthorized according to the forensics, so you should remove it `sudo dnf remove gnome-remote-desktop`. 

### Removed Fred's cronjob
Fred was really persistent about this remote software or it is a very bad remote desktop software to use, so there are a bunch of ways that it starts up on the machine. The cronjob is probably easiest cause most people know about cronjobs and we can find this in /var/spool/cron, you will find a file called fred and simple deleting it will give you points.

### Removed gnome desktop autostart 
So gnome has its own kind of autostart for different services and programs. This is located in the ~/.autostart/ directory so deleting this will gain points. 

### Removed systemd facility to restart gnome-remote-desktop
This one is slightly harder to find, luckily Fred puts this service in a lot of places, in his own user services and in the system services. So to find this you can run `grep -R "gnome-remote-desktop"` the -R option is basically the same as the -r option but follows symlinks and the files are symlinked. Generally when finding stuff you should use the -R option just because it makes sure to check everything. Anyways you will find there will be some files in home and they will be symlinked to some files in /usr/lib/systemd/system and they were called systemd.service. To remove these you can't simply delete these files yourself, you have to use systemctl to delete them or else they will still be loaded in systemctl. So you must run `sudo systemctl disable systemd` and `sudo systemctl --user disable systemd` to gain points.

### Forensics 8:
```
Fred seems to have made a program that he placed on his desktop that was 
created from a compiled file. What was the filename of the source code that the 
program was compiled from?
ANSWER: donot.c
```
After some deep googling(cause google gives different answers for different people), so from what I know, some found the command instantly, I had to do a lot of digging. Anyways, found the command `readelf -s DONOTREADME | grep file` which will display the filename. 

There is no specific other vulnerability tied to this, but in general just best practice to remove the DONOTREADME binary with `sudo rm -rf /home/fred/Desktop/DONOTREADME`

### Forensics 9:
```
Fred seems to have installed a web browser addon that's making regular HTTP 
POST requests. What is the hostname and port that it's making the requests to?
ANSWER: localhost:9200
```
So there is really only one firefox web browser addon and if we go to themes and addons and click inspect we can see the requests being made by the browser. A faster way to get to this mentioned in the hints on the website was just going to `about:debugging` in the web browser.

### Removed malicious browser addon
So the browser addon is obviously very suspicious and is completely unnesecessary and therefore we should remove it. You can do this by going to `about:addons` in the firefox browser, clicking on the extentions tab, clicking on the 3 dots that appear next to an addon and clicking remove addon. 

![Addon Removal Image]()

### Forensics 10:
```
In an effort to try to circumvent the company password restrictions Fred edited 
PAM files to make a call to an external host. What is the domain of that 
external host?

ANSWER: webhook.site
```
The fact that it is known that it is the PAM files makes it pretty easy, just take a parallel fedora image, md5sum all the pam files and compare the hashes to the mr.robot.sh image. There were a few files that didn't lineup uand after looking through the 3 or 4 files one by one we find the changed line. The domains is look the website name that represents the ip address of that host.

### Removed malicious pam module
So after scanning and finding the file that has the malicious changes, you can just restore the file by copying over the original pam.d file into the changed one.

### Forensics 11:
```
Fred was really persistent about trying to keep his remote access tool running. 
It seems that he used a shared object (so) file to try to hide the process 
using an LDPRELOAD technique. What is the name of the shared object that Fred 
is using?
ANSWER: /usr/lib64/libprocesshider/libprocesshider.so
```
Doing some googling, I found something on libprocesshider: [https://github.com/gianlucaborello/libprocesshider](https://github.com/gianlucaborello/libprocesshider) and so I ran `sudo find / -iname *libprocesshider* 2>/dev/null` and it found the .so file. Another easier way was that the LDPRELOAD variable is stored in `/etc/ld.so.preload/` so you can also find it there.

### Removed libprocesshider from ld preload
So this vulnerability for me was a bit buggy. To score points for this just find the /etc/ld.so.preload file and remove everything inside of it. to be able to edit the file, you will need to `sudo chattr -i /etc/ld.so.preload` as it is limited by the attribute. Deleting the file will not score points and that's the way I did it, I deleted the .so files related to the vulnerability and also deleted the original ld.so.preload file. If you have done the same then you can gain points simple with `sudo touch /etc/ld.so.preload`, this will create the file, without anything in it. 

### Forensics 12:
```
Fred has apparently installed a malicious backdoor that's running in javascript 
on port 4444. What is the full path of the javascript file that is running this 
backdoor?
ANSWER: /usr/share/kibana/src/core/server/server.js
```
If you run `ps aux | grep js` or `grep node` and you will find that node is running `/usr/share/kibana/bin/../src/cli/dist`
If you continue to follow this, you see that this runs js files in 4 places, and I went through the stupid process of brute force looking for it which took an ungodly amount of time. The easy way mentioned in hints, is to just run `rpm -Va | grep kibana` and you will find that a js file is one marked with a 5 next to it, meaning the md5sum differs and the file was changed. If you cat that you find it has an eval hex to string line, so the code is encrypted thus grepping for 4444 or any backdoor related commands won't work. Maybe if you are looking for the fact that they would use an eval function that might work, but there are a few other bloated files that do the same, so it would still take a while to find. 

### Removed nodejs web shell
So above there was a part about uninstalling kibana. You should also when uninstalling perform your own purge operations, looking for ways to delete all files related to a service. Like running a `sudo find / -iname *kibana* 2>/dev/null`, and then nodejs is also unnecessary for Fred's purpose for this computer so that can also be removed: `sudo dnf remove nodejs`

### Forensics 13:
```
Fred has somehow managed to retain sudo access without being in the sudoers 
file. What is the full path of the file allowing Fred to retain sudo access?
ANSWER: /etc/sudoers.d/README
```
This one wasn't too hard, there are only a few files that could give Fred sudo access. The first place to look is in teh sudoers.d directory and inside the readme there was an uncommented line giving systemd-root full sudo priviliges and thus that was the answer.

There is also no extra points/vulns related to this vulnerability, you just have to remove that line in the /etc/sudoer.d/README file to fix the problem though.

### Forensics 14 and Disabled rootkit hiding secret.txt:
```
In Fred's home directory, the Documents directory has been zipped and encrypted 
by a ransomware system. The zip is encrypted with a secret key. The key is 
usually stored in a file named secret.txt, but it appears to be hidden. See if 
you can discover the hidden file and decrypt the zip. The zip password is 
historically 20 characters long with upper case, lower case, and numbers.
Inside the directory is an Employee Forms pdf. Please enter the md5sum of the 
pdf here to show that it's been successfully decrypted.

ANSWER: e28d74a368f1f701ea329e7cfc3785c3
```
This one was the hardest, I was given the hints that there was a process hiding a file and that it was a rootkit. The way then was a lot of googling to find the hidden process. If you run normal rootkit scanners like rkhunter, it will find that there are some processes hidden but will not be able to tell you where the rootkit was hidden. How I ended up solving it was while trying to find rootkits, I installed a bunch of software, and updated everything. Apparently running updates on the system breaks a lot of files like nss for Firefox and the rootkit, so we found the secret, ran `unzip Documents.zip` and got the hash with md5sum. 

To actually find the rootkit, we did a lot of googling, and eventually we found a very detailed blog on how to create rootkits: [https://xcellerator.github.io/posts/linux_rootkits_01/](https://xcellerator.github.io/posts/linux_rootkits_01/), which would help later on, didn't read through it fully, just skimmed or else may have found it faster. However, reading it you will understand that it can be made basically impossible to find a rootkit even if you knew it was installed on the system. Solving the Forensic Question displayed the MITRE ATT&CK technique number, after a lot of failed googleing I took a further look at the MITRE ATT&CK entry: [https://attack.mitre.org/techniques/T1547/006/](https://attack.mitre.org/techniques/T1547/006/). It detailed the method of looking for rootkits, through lsmod and mod info in the /lib/modules/kernel-number/ directory. So I went into the directory and tried out the given `modinfo` command on the first .ko file I saw which so happend to be the systemd.ko module that loads the rootkit. The file showed that the author of the rootkit was the earlier blog writer xcellerator, so I knew for sure this was the rootkit and with `lsmod` you can see that the rootkit is running. With `rmmod systemd` you can stop the rootkit. 

---

Full Scoring:

![Full score image]()
