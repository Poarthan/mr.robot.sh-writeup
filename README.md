# [mr.robot.sh](https://tirefire.org/posts/fedora-practice/) Writeup

## The challenge:
The image is linked here: [https://tirefire.org/posts/fedora-practice/](https://tirefire.org/posts/fedora-practice/)

mr.robot.sh is a Fedora practice image created by tirefire, to help students learn about various techniques and how to find them. Therefore there are forensics questions tied to each vulnerability in the image.

### Scenario:

It is company policy to use only Fedora 36 on this computer. It is also company policy to use only the latest, official, stable Fedora 36 packages available for required software and services on this computer. Management has decided that the default web browser for all users on this computer should be the latest stable version of Firefox. Company policy is to never let users log in as root. If administrators need to run commands as root, they are required to use the "sudo" command.

E Corp Workstation

You're an All Safe Employee given this user's workstation to perform forensics and secure it to return it to the user. This is a desktop for Fred. Fred is the only authorized user for this system. Firefox is the only authorized software. All employee duties can be performed in the web browser. Ensure that there are no other services running and that the firewall doesn't allow any remote access.

## Solving:
To start, when you open terminal you are in a rbash(restricted bash) shell where many useful commands don't work. After a bit of googling, we find that the method that works for changing the shell is just `bash` and we enter a normal bash shell. From here on, you should start by solving all the **forensics questions first** before looking to gain any other points, but the writeup will be written in a format where below each forensic will be the vulnerabilities linked to that forensic.

### Firefox installed
This vuln comes with the virtual machine therefore it is a free vulnerability and you will get points for it no matter what.

### T1059.004 Removed restricted bash installed from fedorarepo
The restricted bash is obviously something unnecessary and should thus be deleted. You will score points just by deleting the rbash binary. You can find it with `sudo find / -iname *rbash* 2>/dev/null`

![rbash files](/images/rbash-files.jpg)
Then just remove this stuff with
```
rm -rf /usr/bin/rbash /usr/share/doc/bash/RBASH /var/lib/flatpak/runtime/org.fedoraproject.Platform/x86_64/f37/4e0d584c1eea386081a50b4801f75e7cfd903894b1cc6e7b85db6aabb91c4060/files/share/doc/bash/RBASH
```

### T1195 Fixing DNF repository: Removed fedorarepo yum repository
So if you try to install anything you will find that it doesn't work. So to fix this you go to /etc/yum.repos.d/ and delete all the unnecessary/unusual files, you can figure this out by comparing it to a normal /etc/yum.repos.d and looking for differences. Here are the suspicious ones:

![suspicious repos](/images/sus-repos.jpg)

You can just remove these files with `rm -rf`

### Firewall not allowing external connections and Disabled ssh inbound firewall rule
In the README it says to ensure that 'the firewall doesn't allow any remote access' so this is a clue that there are firewall vulnerabilities. These might be somewhat tricky for those who haven't used the Fedora firewall before because if one follows the fedora docs page, one will be told to use `sudo firewall-cmd --list-all`, but that just lists the firewall rules in the default/public zone, which wasn't where the malicious rules were added to. You also would have a hard time finding these rules with a GUI client like firewall-config.
To find the malicious rules you run `sudo firewall-cmd --list-all-zones` and it will list all the zones on the system. You can find out what all the zones are with `sudo firewall-cmd --get-zones`.
After looking through all the zones you will find that there are some extra unnecessary rules added to the external zone, you can check this with `sudo firewall-cmd --zone=external --list-all`, so to remove these you run `sudo firewall-cmd --zone=external --remove-port=4444/tcp` and `sudo firewall-cmd --zone=external --remove-service=ssh`.

### T1098.004 Forensics 1:
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
SSH keys are usually stored in ~/.ssh, so we look and we find them there, with `ls -al` we can see that the owner is the user nobody. Running `id -u nobody`, we get 65534.

### T1098.004 SSH authorized keys and private keys are not world readable/writable
The SSH keys are linked to another vuln, so fixing the permissions by making the private key and authorized keys permissions 600 and the public key permissions 644, and both are owned by Fred gains points. 

### Forensics 2:
```
Fred has installed another web browser in attempt to use it for remote access.
What is the fedora package name for this other browser that's installed?
ANSWER: chromium.x86_64
```
For this one I ran `sudo dnf list installed | less` and looked through the installed packages for anything that was a web browser, and so this chromium package was found.

![dnf list installed](/images/dnf-installed.jpg)

### Removed Chromium browser
So obviously from reading the readme, this package is unnecessary, therefore, you should uninstall the chromium browser with `sudo dnf remove chromium`.

### T1078 Forensics 3:
```
An Elasticsearch and Kibana frontend have been installed on this host. This is
also called an ELK stack with combined with Logstash. There is a dashboard set
up for the elastic user. What is the title of the dashboard?
ANSWER: Red Wheelbarrow
```
If you just open the website to the local server, you will find that it is called Red Wheelbarrow.

![ELK Stack Dashboard Title](/images/red-wheelbarrow.png)

### Removed kibana service and Removed elasticsearch service
Again the ELK stack is unnecessary therefore you should stop the kibana and elasticsearch services by finding their pids with `ps aux | grep kibana` and `ps aux | grep elastic` and killing them `sudo kill -9 <pid>` then dnf remove the files.

### T1554 Forensics 4:
```
We've had detections of compromised binaries that are backdoored to call out to
the host ifconfig.me. These binaries are present on this host, what are the
md5sums of these binaries so that we can use them as Indicators of Compromise
(IOCs) to share out to the community so that others might also detect when
they're compromised.

ANSWER: 64aa52cfd258963b2398650fa27f43ba
ANSWER: f64577379f87f0df920ee59397de08b2
```
Inside /bin, where binaries are generally stored I ran `grep -r ifconfig.me` and grep will also look for binaries with matches. The results were sudoreplay, curl, wget and sudo. So the answer's should be wget and curl, therefore we can md5sum these 2: `md5sum curl md5sum wget`

### T1554 Removed backdoored curl and Removed backdoored wget
Since these 2 binaries obviously have problems, we need to fix them and the easiest way to do that is to reinstall them with: `sudo dnf reinstall curl` and `sudo dnf reinstall wget`

### T1098 Forensics 5:
```
One of the users on this system is using a non-standard shell that isn't found
in /etc/shells. Which user is it?
ANSWER: /sbin/login
```
All the users and their shells are in /etc/shells. Fred has a normal shell, so it has to be one of the system/service users which most should have a shell like /sbin/nologin or /bin/false. So if we `cat /etc/passwd | grep -v nologin` we filter out most of the normal shells. We see that /sbin/login is the most suspicious of all of them and if you google, you will find the rest of the shells to be default shells for those users.

### 1098 Removed systemd-root user
The user with the shell /sbin/login is the systemd-root user so the obvious next step is to remove that user. You can't just delete the line from /etc/passwd, at least that didn't work for me, but `sudo userdel -f systemd-root` worked, even though after you run the command it will report its being used by another process if you check for evidence in /etc/passwd it won't be there.

### T1195 Forensics 6:
```
Docker was found hosting a service on this system. What is the name of the
docker container that's running?
ANSWER: fedorarepo
```
The first thing I tried was `ps aux | grep docker`, but there was no container name for that. After doing some quick googling we find the command `docker ps --all` and which lists the container name.

### Removed docker
So this docker container should be removed, again similar to removing kibana and elasticsearch, stop the process and then remove all docker related packages:
```
sudo dnf remove docker-ce docker-ce-cli containerd.io docker-compose-plugin
```
You should also remove the docker files from /opt with `sudo rm -rf /opt/containerd` and from root home with `sudo rm -rf /root/Dockerfile`
For some reason all of these don't work and you need to also remove the /run/docker file with `sudo rm -rf /run/docker`

### T1133 Forensics 7:
```
Fred has been detected using remote access software that allows him to log in
from home. This software is not authorized. What is the name of the remote
access software that Fred is using?
ANSWER: gnome-remote-desktop
```
This one took a lot of looking around, eventually, I found that inside the gnome desktop settings, in the sharing section, there was a suspicious remote desktop and after doing some research, I found that this was Gnome's Remote desktop.
![Found Remote Desktop](/images/remote-desktop-sus.jpg)

For some reason I didn't find it with dnf but if you run `sudo dnf list installed | less` and search for remote with `/remote` and navigate around with `n` then you will find gnome-remote-desktop.

### Removed gnome-remote-desktop
The remote desktop software is unauthorized according to the forensics, so you should remove it `sudo dnf remove gnome-remote-desktop`.

### T1053.003 Removed Fred's cronjob
Fred was really persistent about this remote software or it is a very bad remote desktop software to use, so there are a bunch of ways that it starts up on the machine. The cronjob is probably easiest because most people know about cronjobs and we can find this in /var/spool/cron, you will find a file called fred, and simple deleting it will give you points.

### T1053.003 Removed gnome desktop autostart
So gnome has its own kind of autostart for different services and programs. This is located in the ~/.config/autostart directory so deleting this will gain points.

### Removed systemd facility to restart gnome-remote-desktop
This one is slightly harder to find, luckily Fred puts this service in a lot of places, in his own user services and in the system services. So to find this you can run `grep -R "gnome-remote-desktop"` the -R option is basically the same as the -r option but follows symlinks and the files are symlinked. Generally, when finding stuff you should use the -R option just because it makes sure to check everything. Anyways you will find there will be some files in home and they will be symlinked to some files in /usr/lib/systemd/system and they were called systemd.service. To remove these you can't simply delete these files yourself, you have to use systemctl to delete them, or else they will still be loaded in systemctl. So you must run `sudo systemctl disable systemd` and `systemctl --user disable systemd` first, then delete the original systemd.service files and the ran exec file with `sudo rm -rf /usr/lib/systemd/system/systemd.service /usr/lib/systemd/systemd.timer /home/fred/.config/systemd`

### T1204.002 Forensics 8:
```
Fred seems to have made a program that he placed on his desktop that was
created from a compiled file. What was the filename of the source code that the
program was compiled from?
ANSWER: donot.c
```
After some deep googling(cause google gives different answers for different people), so from what I know, some found the command instantly, I had to do a lot of digging. Anyways, found the command `readelf -s DONOTREADME | grep -i file` which will display the filename.

There is no specific other vulnerability tied to this, but in general, just best practice to remove the DONOTREADME binary with `sudo rm -rf /home/fred/Desktop/DONOTREADME`

### T1176 Forensics 9:
```
Fred seems to have installed a web browser addon that's making regular HTTP
POST requests. What is the hostname and port that it's making the requests to?
ANSWER: localhost:9200
```
So to look at it, just go to `about:debugging` and click on inspect.

![Inspect Addon](/images/inspect-addon.jpg)

### T1176 Removed malicious browser addon
So the browser addon is obviously very suspicious and is completely unnecessary and therefore we should remove it. You can do this by going to `about:addons` in the firefox browser, clicking on the extensions tab, clicking on the 3 dots that appear next to an addon and clicking remove addon.

![Addon Removal Image](/images/addon-removal.png)

### T1136.002 Forensics 10:
```
In an effort to try to circumvent the company password restrictions Fred edited
PAM files to make a call to an external host. What is the domain of that
external host?

ANSWER: webhook.site
```
Since we know this is in PAM, you can just go through the pam files with something like `cat * | less` and find the unusual entry. Or you can just compare against defaults.

![external host for pam](/images/pam-sus.jpg)

### T1136.002 Removed malicious pam module
You can just remove the malicious lines from teh file

### T1574.006 Forensics 11:
```
Fred was really persistent about trying to keep his remote access tool running.
It seems that he used a shared object (so) file to try to hide the process
using an LDPRELOAD technique. What is the name of the shared object that Fred
is using?
ANSWER: /usr/lib64/libprocesshider/libprocesshider.so
```
Doing some googling, I found something on libprocesshider: [https://github.com/gianlucaborello/libprocesshider](https://github.com/gianlucaborello/libprocesshider) and so I ran `sudo find / -iname *libprocesshider* 2>/dev/null` and it found the .so file. Another easier way was that the LDPRELOAD variable is stored in `/etc/ld.so.preload/` so you can also find it there.

### T1574.006 Removed libprocesshider from ld preload
So this vulnerability for me was a bit buggy. To score points for this just find the /etc/ld.so.preload file and remove everything inside of it. to be able to edit the file, you will need to `sudo chattr -i /etc/ld.so.preload` as it is limited by the attribute. Deleting the file will not score points and that's the way I did it, I deleted the .so files related to the vulnerability and also deleted the original ld.so.preload file. If you have done the same then you can gain points simply with `sudo touch /etc/ld.so.preload`, this will create the file, without anything in it.

### T1505.003 Forensics 12:
```
Fred has apparently installed a malicious backdoor that's running in javascript
on port 4444. What is the full path of the javascript file that is running this
backdoor?
ANSWER: /usr/share/kibana/src/core/server/server.js
```
If you run `ps aux | grep js` or `ps aux | grep node` and you will find that node is running /usr/share/kibana/bin/../src/cli/dist
If you continue to follow this, you see that this runs js files in 4 places, and I went through the stupid process of brute force looking for it which took an ungodly amount of time. The easy way mentioned in hints, is to just run `rpm -Va | grep kibana` and you will find that a js file is one marked with a 5 next to it, meaning the md5sum differs and the file was changed. If you cat that you find it has an eval hex to string line, so the code is encrypted thus grepping for 4444 or any backdoor related commands won't work. Maybe if you are looking for the fact that they would use an eval function that might work, but there are a few other bloated files that do the same, so it would still take a while to find.

### T1053.003 Removed nodejs web shell
So above there was a part about uninstalling kibana. You should also when uninstalling perform your own purge operations, looking for ways to delete all files related to a service. Like running a `sudo find / -iname *kibana* 2>/dev/null`, and then nodejs is also unnecessary for Fred's purpose for this computer so that can also be removed: `sudo dnf remove nodejs`

### T1548.003 Forensics 13:
```
Fred has somehow managed to retain sudo access without being in the sudoers
file. What is the full path of the file allowing Fred to retain sudo access?
ANSWER: /etc/sudoers.d/README
```
This one wasn't too hard, there are only a few files that could give Fred sudo access. The first place to look is in the sudoers.d directory and inside the readme there was an uncommented line giving systemd-root full sudo priviliges and thus that was the answer.

There is also no extra points/vulns related to this vulnerability, you just have to remove that line in the /etc/sudoer.d/README file to fix the problem though.

### T1547.006 Forensics 14 and Disabled rootkit hiding secret.txt:
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
This one was hard, the way that ended up working was to go to /lib/modules/something and modinfoing the first .ko file which was systemd.ko, so `modinfo systemd.ko` and recognizing it was a rootkit. Then you can remove this rootkit with `rmmod systemd`.

A better way someone had of finding it was looking through /etc/modules-loaded.d/ directory which lists all additional kernel modules loaded at boot and you will instantly konw that systemd was the suspect one. Removing this file will also remove persistence of the rootkit if one reboots the image. 

The rootkit was created with [https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques/3.4_hiding_directories](https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques/3.4_hiding_directories), if anyone wants to do more research into rootkits, they can check out Xcellerator's blog: [https://xcellerator.github.io/posts/linux_rootkits_01/](https://xcellerator.github.io/posts/linux_rootkits_01/).

---

Full Scoring:

![Full score image](/images/full-score.jpg)
