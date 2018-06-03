#!/bin/bash

# DEFINE KEY VARIABLES HERE!
DEF_USER="foobar"
KRB_REALM="AD.EXAMPLE.COM"
DOMAIN="FOONET"
HOSTNAME=""
IP=$(/sbin/ip -o -4 addr list eth0 | awk '{print $4}' | cut -d/ -f1)
DNS_FW="10.0.0.5"       # Use your DNS FW
ADMIN_PW="Passw0rd!"
ALLOW_ROOT_SSH_FROM="10.0.*,172.25.20.*"    # Customize this

# ------------ DO NOT MODIFY UNDER THIS LINE ------------
# (well, you can, but you should know what you're doing)
# Note 1: Locale settings are hardcoded for en_US.UTF-8
# 	  below in the stage one function.
# Note 2: Please review password requirements for domain users
#	  which are set at end of stage five function

# PATHs and EXECUTABLEs
WORKDIR=`pwd`/workspace
SYSVOL="/var/lib/samba/sysvol"
SB_TOOL="/usr/bin/samba-tool"

RBT_DELAY=10	# Delay x seconds before reboot (for user to read output and cancel if necessary)
Slog=deploy-stage
LOG=$(ls deploy-stage*)

get_inputs() {
	# Function which asks user for inputs (or confirm defaults)
	# Then outputs these to log file - from which they'll be read
	# in subsequent stages

	clear
	inp=""
	read -p "Unix user which will be assigned sudo privileges [${DEF_USER}]: " inp
	[ ! -z "${inp}" ] && DEF_USER="${inp}"
	read -p "Kerberos realm to use for Active Direcotry [${KRB_REALM}]: " inp
	[ ! -z "${inp}" ] && KRB_REALM="${inp}"
	read -p "Active directory Domain to be used [${DOMAIN}]: " inp
	[ ! -z "${inp}" ] && DOMAIN="${inp}"
	read -p "Hostname of this computer [$(hostname)]: " inp
	[ ! -z "${inp}" ] && HOSTNAME="${inp}" || HOSTNAME=$(hostname)
	read -p "IP address of (!)this(!) domain controller [${IP}]: " inp
	[ ! -z "${inp}" ] && IP="${inp}"
	read -p "DNS forwarder to use to resolve hostnames outside AD [${DNS_FW}]: " inp
	[ ! -z "${inp}" ] && DNS_FW="${inp}"
	read -p "Password for Active directory domain Administrator account [${ADMIN_PW}]: " inp
	[ ! -z "${inp}" ] && ADMIN_PW="${inp}"

	echo "Configuration will use these values:" >> "${1}"
	echo "User=$DEF_USER" >> "${1}"
	echo "Kerberos_realm=$KRB_REALM" >> "${1}"
	echo "Domain=$DOMAIN" >> "${1}"
	echo "Hostname=$HOSTNAME" >> "${1}"
	echo "IP_address=$IP" >> "${1}"
	echo "DNS_Forwarder=$DNS_FW" >> "${1}"
	echo "Domain_admin_password=$ADMIN_PW" >> "${1}"
	echo "Mode_is=$MODE" >> "${1}"
	echo "Build_from_source=$BFS" >> "${1}"
}

read_inputs() {
	# Function reads the main variables from the status file
	# $1 -> Pass current status file as argument

	while IFS='' read -r line || [[ -n "$line" ]]; do
		case "$line" in
			User=*)
				DEF_USER="${line#*=}"
				;;
			Kerberos_realm=*)
				KRB_REALM="${line#*=}"
				;;
			Domain=*)
				DOMAIN="${line#*=}"
				;;
			Hostname=*)
				HOSTNAME="${line#*=}"
				;;
			IP_address=*)
				IP="${line#*=}"
				;;
			DNS_Forwarder=*)
				DNS_FW="${line#*=}"
				;;
			Domain_admin_password=*)
				ADMIN_PW="${line#*=}"
				;;
			Mode_is=*)
				MODE="${line#*=}"
				;;
			Build_from_source=*)
				BFS="${line#*=}"
				;;
		esac
	done < "${1}"
}

stage_start_log() {
	# Functin updates the filename of the status file
	# at the beginning of each stage and writes basic info

	[ -f "${1}" ] && mv "${1}" "${2}" || touch "${2}"

	echo "Deployment of Active Directory started" >> "${2}"
	echo "______________________________________" >> "${2}"
	echo "Stage started at: "$(date) >> "${2}"
}

# Stage 1 function
perform_stage_one() {
	# In this stage: (we modify some debian defaults)
	#  -> disable CD-ROM apt source if enabled
	#  -> update and upgrade package sources
	#  -> fix Locale settings (hard coded to English US -> feel free to change)
	#  -> modify /etc/resolv.conf and make it immutable
	#	(set this host as nameserver, set search to kerberos realm, and set forward DNS)

	D1="${Slog}1"
	stage_start_log "${D1}" "${D1}"
	get_inputs "${D1}"
	# Fix apt sources (comment out CD-ROM)
	echo "Disable CD-ROM as package source..." | tee -a "${D1}"
	sed -i 's/deb cdrom:/# deb cdrom:/' /etc/apt/sources.list && echo "Sources fix OK" | tee -a "${D1}"

	# Update sources
	apt-get update
	apt-get -y upgrade

	# Fix LOCALE settings
	echo "Fixing locale settings..." | tee -a "${D1}"
	mv /etc/default/locale /etc/default/locale-`date '+%Y%m%d'`
	echo 'LC_TYPE="en_US.UTF-8"' >> /etc/default/locale && \
	echo 'LC_ALL="en_US.UTF-8"' >> /etc/default/locale && \
	echo 'LANGUAGE="en_US:en"' >> /etc/default/locale && \
	echo 'LANG="en_US.UTF-8"' >> /etc/default/locale && echo "Locale fix OK" >> "${D1}"
	echo "Locales fixed. Reboot required!"

	# User_xattr check and mount
	# DEPRECATED(?) - YES, Debian already uses xattr and acl by default.
	# I keep it here in case someone wants to modify it for different system
		#	FFILE="/etc/fstab"
		#	cp -pRf ${FFILE} ${FFILE}-bkp && \
		#	cp -pRf ${FFILE} ${FFILE}-`date '+%Y%m%d'` && \
		#	sed 's/^UUID.* \/ .*errors=remount-ro/&,user_xattr,acl,barrier=1/' ${FFILE} > ${FFILE}-new && \
		#	mv ${FFILE}-new ${FFILE} && echo "fstab modification OK" >> ~/deploy-stage1

	# Modify resolv.conf and make it immutable
	echo "Modifying resolv.conf..." | tee -a "${D1}"
	FFILE="/etc/resolv.conf"
	cp -pRf "${FFILE}" "${FFILE}"-$(date '+%Y%m%d')
	rm "${FFILE}"
	echo "nameserver ${IP}" > "${FFILE}"
	echo "search ${KRB_REALM}" >> "${FFILE}"
	echo "nameserver ${DNS_FW}" >> "${FFILE}"
	chattr +i "${FFILE}"
	service networking restart && echo "OK" | tee -a "${D1}"

	echo "Rebooting in ${RBT_DELAY} seconds..." | tee -a "${D1}" && sleep "${RBT_DELAY}"
	echo " >>>>>>>>> Stage 1 finished at: "$(date)" <<<<<<<<<<<" >> "${D1}"
	shutdown -r now
}

# *** >>> *** STAGE TWO *** <<< ***
perform_stage_two() {
	# In this stage: (setup ssh and a sudo user options - required for later)
	#  >> SSH <<
	#	-> install openssh-server
	#	-> modify cnfiguration (especially exception who can login and how)
	#	-> (enable password authentication, disable root login, permit root key based login from local net)
	# >> Default user << (user which was set up during debian install [or any other chosen existing user])
	#	-> add to sudoers and set no password required

	D2="${Slog}2"
	stage_start_log "${Slog}1" "${D2}"
	read_inputs "${D2}"

	echo "Welcome back :) to stage 2 of the Active Directory automated deployment."

	# DEPRECATED -> see stage one for more info
		#	echo "Checking EXT4 file system user_xattr option:" >> ~/deploy-stage2
		#	grep CONFIG_EXT4_FS /boot/config-`uname -r` >> ~/deploy-stage2
		#	sTMP=`grep _FS_XATTR=y ~/deploy-stage2`
		#	[ -z "${sTMP}" ] && echo "user_xattr NOT FOUND" >> ~/deploy-stage2 && echo "USER XATTR critical stop." && exit 2

	# Install required packages
	echo "Installing basic packages..." | tee -a "${D2}"
	apt-get -y install sudo openssh-server

	echo "Modifying OpenSSH configuration..." | tee -a "${D2}"
	FFILE="/etc/ssh/sshd_config"
	cp -pRf "${FFILE}" "${FFILE}"-$(date '+%Y%m%d')
	sed -i 's/^PermitRootLogin without-password/PermitRootLogin no/' "${FFILE}"
	sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' "${FFILE}"
	echo "" >> "${FFILE}" \
		&& echo "# Override some settings for local subnets and VPN" >> "${FFILE}" \
		&& echo "Match address ${ALLOW_ROOT_SSH_FROM}" >> "${FFILE}" \
		&& echo "    PasswordAuthentication yes" >> "${FFILE}" \
		&& echo "    PermitRootLogin without-password" >> "${FFILE}"
	echo "Restarting SSH server..." | tee -a "${D2}"
	service ssh restart && echo "OK" | tee -a "${D2}"

	#User which is defined during debaian install is added to sudo group
	echo "Adding user ${DEF_USER} to sudo group..." | tee -a "${D2}"
	adduser "${DEF_USER}" sudo && echo "OK" | tee -a "${D2}"
	echo "Modifying sudoers file..." | tee -a "${D2}"
	echo "${DEF_USER} ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers && echo "OK" | tee -a "${D2}"
	echo ""
	echo "STAGE TWO COMPLETED..."
	echo "Stage 3 will begin in 10 seconds, unless you want to reboot."
	inp="n"
	reboot -n 1 -t "${RBT_DELAY}" "Do you want to reboot? [y/n]" inp
	echo "Stage 2 finished" | tee -a "${D2}"
	[ "${inp}" == "y" ] && shutdown -r now
}

build_from_source() {
	# WARNING --> This is not really well tested... please use default packages instead!
	#	I kept getting errors while doing self-test (which is strange, but...)
	#	(if you still want to compile, you will have to modify hard-coded samba locations
	#	 such as sysvol etc., later in the script - as packaged version differs from
	#	 default compile options)

	# This function installs required packages for compiling and attempts to compile and install
	# samba from its source

	apt-get -y install acl attr autoconf bison build-essential debhelper \
		dnsutils docbook-xml flex gdb libjansson-dev krb5-user libacl1-dev libaio-dev \
		libarchive-dev libattr1-dev libblkid-dev libbsd-dev libcap-dev libcups2-dev \
		libgnutls28-dev libgpgme11-dev libjson-perl libldap2-dev libncurses5-dev libpam0g-dev \
		libparse-yapp-perl libpopt-dev libreadline-dev nettle-dev perl perl-modules pkg-config \
		python-all-dev python-crypto python-dbg python-dev python-dnspython python3-dnspython \
		python-gpgme python3-gpgme python-markdown python3-markdown python3-dev xsltproc \
		zlib1g-dev git autoconf ntp \
	&& echo "OK" | tee -a "${D3}"

	if [ ! -d "${WORKDIR}" ]; then
		mkdir -p "${WORKDIR}" || { echo "workdir ${WORKDIR} failed" >> ${D3} && echo "Workdir creation failed" && exit 4 ; }
	fi
	cd "${WORKDIR}" && echo "workdir ${WORKDIR} ok" >> "${D3}"

	echo "Downloading source..." | tee -a "${D3}"
	answer="n"
	# If we already have the source, ask whether to re-download it
	if [ -d "${WORKDIR}/samba4" ]; then
		echo ">>>>>>>>>>>>>>>>>>> <<<<<<<<<<<<<<<<<<<"
		echo "Source already found in working directory!"
		echo "You can try to keep it..."
		read -t "${RBT_DELAY}" -n 1 -p "Do you want to re-download (y/n)? " answer
		if [ "${answer}" != "y" ]; then
			answer="n"
			echo "Keeping source." | tee -a "${D3}"
		else
			rm -r "${WORKDIR}/samba4"
			git clone git://git.samba.org/samba.git samba4 && echo "OK" | tee -a "${D3}"
		fi
	else
		git clone git://git.samba.org/samba.git samba4 && echo "OK" | tee -a "${D3}"
	fi

	echo "Running configure and make..." | tee -a "${D3}"
	sleep 5
	cd samba4
	./configure --enable-debug --enable-selftest
	make | tee -a "${D3}.make" && echo "OK" | tee -a "${D3}"

	# Do validation... dump to a file... check end for all ok then...
	# if all ok, inform and install
	# otherwise ask to abort or try installing
	make quicktest | tee -a ~/quicktest.log
	result=$(grep "ALL OK" ~/quicktest.log)
	[ -z "${result}" ] && echo "Make quicktest failed" | tee -a "${D3}" && exit 4

	# Install samba
	make install
}

use_packaged_version() {
	# THIS IS THE PREFERRED METHOD OF INSTALLING SAMBA (for this script at least)
	#
	# Function isntalls required packages for samba AD, including kerberos, winbind, ntp, cups

	apt-get -y install samba krb5-user krb5-config krb5-pkinit winbind smbclient ntp \
		&& echo "Packages group 1 (including recommends) - installed ... OK" | tee-a "${D3}"

	# We do not want CUPS to install AVAHI (recommended package), so here goes...
	apt-get -y install --no-install-recommends cups cups-driver-gutenprint cups-pdf cups-ppdc \
		&& echo "Packages group 2 (no recommends) installed ... OK" | tee -a "${D3}"

	mv /etc/samba/smb.conf /etc/samba/smb.conf-$(date '+%Y%m%d')
}

perform_stage_three() {
	# In this stage:
	#  -> install packaged samba from repository (or compile from source)
	#  -> install and configure ntp
	#  -> install and configure kerberos

	D3="${Slog}3"
	stage_start_log "${Slog}2" "${D3}"
	read_inputs "${D3}"

	echo "Script will use: "
	[ "${BFS}" == "yes" ] && echo "'Compile from source files' samba" || echo "'Packaged version' of samba"
	echo "Build From Source = ${BFS}" >> "${D3}"
	echo ""
	echo "_______ READ BELOW _______"
	echo "Installing required packages..." | tee -a "${D3}"
	echo "NOTE - when asked, please use:"
	echo "KERBEROS REALM: ${KRB_REALM}"
	echo "Kerberos servers (both prompts): ${HOSTNAME}.${KRB_REALM}"
	echo "...continuing in 10 seconds... " && sleep 10
	if [ "${BFS}" == "yes" ]; then
		build_from_source
	else
		use_packaged_version
	fi

	echo "NTP server..." | tee -a "${D3}"
		cp -pRf /etc/ntp.conf /etc/ntp.conf-$(date '+%Y%m%d')
		echo "# DOMAIN DEPLOY SCRIPT" >> /etc/ntp.conf && \
		echo "ntpsigndsocket /usr/local/samba/var/lib/ntp_signd/" >> /etc/ntp.conf && \
		echo "restrict default mssntp" >> /etc/ntp.conf && \
	echo "OK" | tee -a "${D3}"

	echo "Before we proceed with domain provision, we recommend to restart..."
	echo "Stage 3 finished... rebooting in ${RBT_DELAY} seconds" | tee -a "${D3}"
	sleep "${RBT_DELAY}" && shutdown -r now
}

perform_stage_four() {
	# In this stage:
	#	-> configure AD depending whether it is the first AD domain controller ("new")
	#	   or if we are joining an already existing domain as next DC
	#  >>new<<
	#	-> prepare for sysvol replication (we will ssh into other hosts and perform sysvol repl)
	#		-> will use osync method -> install rsync, ssh client, osync script
	#	-> provision AD domain
	# >>join<<
	#	-> install rsync
	#	-> get public key from 'main' DC
	#	-> modify kerberos conf file
	#	-> join samba to existing domain controler
	#	-> deploy osync conf file for this DC onto the 'main' DC
	#	-> setup cron job on 'main' DC for sysvol replication to this host
	#
	# finally, we enable samaba AD daemon and disable normal samba daemons and start them

	D4="${Slog}4"
	stage_start_log "${Slog}3" "${D4}"
	read_inputs "${D4}"

	echo "Started at: "$(date) >> "${D4}"

	case "${MODE}" in
		"new")
			echo "Preparring for possible future sysvol replication..."
			echo "Installing required packages for 'osync' replication tool..." | tee -a "${D4}"
			apt-get -y install rsync openssh-client sshpass \
			        && echo "OK" | tee -a "${D4}"
			echo "Downloading 'osync' latest stable release..." | tee -a "${D4}"
			wget https://github.com/deajan/osync/archive/stable.tar.gz
			if [ $? -eq 0 ]; then
			        echo "OK" | tee -a "${D4}"
			        echo "Extracting source..." | tee -a "${D4}"
			        tar xf stable.tar.gz && rm stable.tar.gz && echo "OK" | tee -a "${D4}"
			        echo "Installing 'osync' ..." | tee -a "${D4}"
			        cd osync-stable \
			                && bash install.sh --silent --no-stats \
			                && cd .. \
					&& echo "OK" | tee -a "${D4}"
			else
			        echo "WARNING! Download failed... 'osync' will not be installed!" | tee -a "${D4}"
			fi
			echo "Generating key-pair..." | tee -a "${D4}"
			ssh-keygen -t rsa -q -f ~/.ssh/id_rsa -N '' && echo "OK" | tee -a "${D4}"
			# Actual osync configurations for sysvol replication will be added
			# from this script when run on DC joining this AD ("join" option)

			echo "Starting domain provision..." | tee -a "${D4}"
			samba-tool domain provision \
				--realm="${KRB_REALM}" \
				--domain="${DOMAIN}" \
				--adminpass="${ADMIN_PW}" \
				--server-role='domain controller' \
				--dns-backend='SAMBA_INTERNAL' \
				--use-rfc2307 \
			&& echo "OK" | tee -a "${D4}"
			sed -i "/dns forwarder/c\    dns forwarder = ${DNS_FW}" /etc/samba/smb.conf \
				&& echo "Modify forwarder in smb.conf file ... OK" | tee -a "${D4}"
			cp -pRf /var/lib/samba/private/krb5.conf /etc/ \
				&& echo "Kerberos conf copied." | tee -a "${D4}"
			;;
		"join")
			# This part is used when joining DC to already existing AD
			echo "Installing rsync for sysvol replication" | tee -a "${D4}"
			apt-get -y install rsync && echo "OK" | tee -a "${D4}"
			# Get public key from the "main" DC
			ssh -t ${DEF_USER}@${Main_AD} \
				"sudo sh -c 'ssh-copy-id -i /root/.ssh/id_rsa.pub ${DEF_USER}@${IP}'"
			echo "Modify kerberos config file..." | tee -a "${D4}"
			mv /etc/krb5.conf /etc/krb5.conf.$(date '+%Y%m%d')
			echo "[libdefaults]" >> /etc/krb5.conf
			echo "		dns_lookup_realm = false" >> /etc/krb5.conf
			echo "		dns_lookup_kdc = true" >> /etc/krb5.conf
			echo "		default_realm = ${KRB_REALM}" >> /etc/krb5.conf
			echo "OK" | tee -a "${D4}"

			echo "You will be asked for AD domain administrator password:"
			echo "Joining DC to an existing domain..." | tee -a "${D4}"
			samba-tool domain \
				join "${KRB_REALM}" DC \
				-U"${DOMAIN}\administrator" \
				--dns-backend=SAMBA_INTERNAL \
				--option='idmap_ldb:use rfc2307 = yes' \
			&& echo "OK" | tee -a "${D4}"

			# The following only works, if the user with sudo rights is the same
			# as on the main AD controller and on the main controller that user
			# has sudo privileges (ideally without password, as set-up by this script)
			echo "Copying SysVol database..." | tee -a "${D4}"
			/etc/init.d/samba-ad-dc stop
			sleep 4
			Main_AD=$(nslookup ${KRB_REALM} | awk '/^Address: / { print $2 ; exit }')
			[ -z "${Main_AD}" ] \
				&& echo "Critical stop! Can't resolv realm's IP. Quitting!" | tee -a "${D4}" \
				&& exit 5

			echo "Main AD: ${Main_AD}" >> "${D4}"
			OSYNC_CONF="/etc/osync/${HOSTNAME}.conf"

			ssh -T ${DEF_USER}@${Main_AD} <<- EOSSH
				sudo touch "${OSYNC_CONF}"
				sudo chmod 666 "${OSYNC_CONF}"
				cat > "${OSYNC_CONF}" <<- EOM
		#!/usr/bin/env bash
		INSTANCE_ID="sysvol_sync"
		INITIATOR_SYNC_DIR="${SYSVOL}"
		TARGET_SYNC_DIR="ssh://${DEF_USER}@${IP}:22/${SYSVOL}"
		SSH_RSA_PRIVATE_KEY="/root/.ssh/id_rsa"
		SSH_PASSWORD_FILE=""
		_REMOTE_TOKEN="SomeAlphaNumericToken9"
		REMOTE_3RD_PARTY_HOSTS=""
		RSYNC_OPTIONAL_ARGS=""
		PRESERVE_PERMISSIONS="yes"
		PRESERVE_OWNER="yes"
		PRESERVE_GROUP="yes"
		PRESERVE_EXECUTABILITY="yes"
		PRESERVE_ACL="yes"
		PRESERVE_XATTR="yes"
		COPY_SYMLINKS="no"
		KEEP_DIRLINKS="no"
		PRESERVE_HARDLINKS="no"

		CHECKSUM="no"
		RSYNC_COMPRESS="yes"
		SOFT_MAX_EXEC_TIME="7200"
		HARD_MAX_EXEC_TIME="10600"
		KEEP_LOGGING="1801"
		MIN_WAIT="60"
		MAX_WAIT="7200"
		CONFLICT_BACKUP="yes"
		CONFLICT_BACKUP_MULTIPLE="no"
		CONFLICT_BACKUP_DAYS="30"
		CONFLICT_PREVALANCE="initiator"

		SOFT_DELETE="yes"
		SOFT_DELETE_DAYS="30"
		SKIP_DELETION=""
		RESUME_SYNC="yes"
		RESUME_TRY="2"
		FORCE_STRANGER_LOCK_RESUME="no"
		PARTIAL="no"
		DELTA_COPIES="yes"
		CREATE_DIRS="yes"
		LOGFILE=""
		MINIMUM_SPACE="10240"
		BANDWIDTH="0"

		SUDO_EXEC="yes"
		RSYNC_EXECUTABLE="rsync"
		RSYNC_REMOTE_PATH=""
		RSYNC_PATTERN_FIRST="include"
		RSYNC_INCLUDE_PATTERN=""
		RSYNC_EXCLUDE_PATTERN=""
		RSYNC_INCLUDE_FROM=""
		RSYNC_EXCLUDE_FROM=""
		PATH_SEPARATOR_CHAR=";"

		SSH_COMPRESSION="no"
		SSH_IGNORE_KNOWN_HOSTS="no"
		REMOTE_HOST_PING="no"

		DESTINATION_MAILS="your@email.com"
		MAIL_BODY_CHARSET=""
		SENDER_MAIL="alert@your.system.tld"
		SMTP_SERVER="smtp.your.isp.tld"
		SMTP_PORT="25"
		SMTP_ENCRYPTION="none"
		SMTP_USER=""
		SMTP_PASSWORD=""

		LOCAL_RUN_BEFORE_CMD=""
		LOCAL_RUN_AFTER_CMD=""
		REMOTE_RUN_BEFORE_CMD=""
		REMOTE_RUN_AFTER_CMD="sudo ${SB_TOOL} ntacl sysvolreset"
		MAX_EXEC_TIME_PER_CMD_BEFORE="0"
		MAX_EXEC_TIME_PER_CMD_AFTER="0"
		STOP_ON_CMD_ERROR="yes"
		RUN_AFTER_CMD_ON_ERROR="no"
EOM
	sudo chmod 644 "${OSYNC_CONF}"
	(sudo crontab -u root -l ; echo "*/5 * * * * root  /usr/local/bin/osync.sh ${OSYNC_CONF} --silent") 2>&1 | grep -v "no crontab" | sort | uniq | sudo crontab -u root -
EOSSH
			;;
			# End of 'join'
	esac

	# Set daemons and start samba
	echo "Setting up daemons and starting samba" | tee -a "${D4}"
	systemctl disable nmbd && echo "Disable nmbd... OK" | tee -a "${D4}"
	systemctl disable smbd && echo "Disable smbd... OK" | tee -a "${D4}"
	systemctl stop nmbd && echo "Stop nmbd... OK" | tee -a "${D4}"
	systemctl stop nmbd && echo "Stop smbd... OK" | tee -a "${D4}"
	systemctl unmask samba-ad-dc && echo "Unmask samba-ad-dc ... OK" | tee -a "${D4}"
	systemctl enable samba-ad-dc && echo "Enable samba-ad-dc ... OK" | tee -a "${D4}"
	systemctl start samba-ad-dc && echo "Start samba-ad-dc ... OK" | tee -a "${D4}"
	echo "Samba daemons configured. Reboot required." | tee -a "${D4}"
	echo "Stage 4 finished. Rebooting in ${RBT_DELAY} seconds."
	sleep "${RBT_DELAY}" && shutdown -r now

}

perform_stage_five() {
	# In this stage:
	#	-> we run some basic tests for our newly set-up DC
	#	-> modify password requirements for AD users
	# (These tests are for user review, and do not provide any additional functionality
	#  above that deplaoyed in previous stage)

	D5="${Slog}5"
	stage_start_log "${Slog}4" "${D5}"
	read_inputs "${D5}"

	echo "Started at: "$(date) >> "${D5}"

	echo "Starting basic tests:" | tee -a "${D5}"
	samba_dnsupdate --verbose | tee -a "${D5}"
	host -t A "${HOSTNAME}.${KRB_REALM}" | tee -a "${D5}"
	host -t SRV _ldap._tcp."${KRB_REALM}" | tee -a "${D5}"
	kinit administrator@"${KRB_REALM}" | tee -a "${D5}"

	# Finally modify password settings (note: not all can be set via RSAT! e.g. password complexity)
	if [ "${MODE}" == "new" ]; then
		echo "Adjusting domain password settings..." | tee -a "${D5}"
		samba-tool domain passwordsettings set --complexity=off | tee -a "${D5}"
		samba-tool domain passwordsettings set --history-length=0 | tee -a "${D5}"
		samba-tool domain passwordsettings set --min-pwd-age=0 | tee -a "${D5}"
		samba-tool domain passwordsettings set --max-pwd-age=0 | tee -a "${D5}"
		samba-tool user setexpiry Administrator --noexpiry | tee -a "${D5}"
	fi
	echo "Stage 5 finished." | tee -a "${D5}"
}

show_usage() {
	echo "Usage:"
	echo "$0 [new|join] [--restart] [--from-source]"
	echo "   'new' - (default) to create a new Active directory DC"
	echo "   'join' - to join an existing active direcotry domain"
	echo "   --restart - forces the script to start from stage 1, regardless of progress so far"
	echo "   --from-source - the script will try to compile samba from source, instead of using packages"
	echo "   --help - show this text"
	echo
	echo "Mode cannot be changed between stages. Once deployment is started with e.g. 'join',"
	echo "then all remaining stages will use this mode, regardless of command line option."
	echo
	exit 1
}

# MAIN SCRIPT STARTS HERE

# Check if root
[ `id -u` != 0 ] && echo "You must run this script as root!" && exit 1

MODE="new"
BFS="no"
while [[ $# -gt 0 ]]
do

	case "$1" in
		"new"|"join")
			MODE="$1"
			shift
			;;
		"--restart")
			rm -f "${Slog}"*
			rm -f "${Slog%/*}"/quicktest.log
			shift
			;;
		"--from-source")
			BFS="yes"
			shift
			;;
		"--help")
			show_usage
			;;
		*)
			show_usage
		;;
	esac
done


[ -z "${LOG}" ] && [ ! -f "${Slog}1" ] && perform_stage_one
[ ! -z "${LOG}" ] && [ -f "${Slog}1" ] && perform_stage_two
[ ! -z "${LOG}" ] && [ -f "${Slog}2" ] && perform_stage_three
[ ! -z "${LOG}" ] && [ -f "${Slog}3" ] && perform_stage_four
[ ! -z "${LOG}" ] && [ -f "${Slog}4" ] && perform_stage_five

echo "Deployment process finished! Thank you and bye."
