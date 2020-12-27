#!/bin/bash
# Script to show changelog entries

basedn="dc=my-domain,dc=com"

admindn="cn=Manager,dc=my-domain,dc=com"
adminpwd="secret"

ldapsearch -x -D $admindn -w $adminpwd -b cn=changelog
