#!/bin/bash
# Script to test all operations that can be stored in the changelog

basedn="dc=my-domain,dc=com"

admindn="cn=Manager,dc=my-domain,dc=com"
adminpwd="secret"

echo "Adding $basedn";

ldapadd -x -D $admindn -w $adminpwd << EOF
dn: $basedn
objectClass: organization
objectClass: dcObject
o: MyCompany
EOF

echo "Adding o=test,$basedn..."

ldapadd -x -D $admindn -w $adminpwd << EOF
dn: o=test,$basedn
objectClass: organization
o:test
EOF

echo "* Adding cn=user1,o=test,$basedn..."

ldapadd -x -D $admindn -w $adminpwd << EOF
dn: cn=user1,o=test,$basedn
objectClass: organizationalPerson
sn: Doe
l: City
street: Street
st: State
telephoneNumber: 1234567890
description: This is just a simple test user
EOF

echo "* Modifying description of cn=user1,o=test,$basdn..."

ldapmodify -x -D $admindn -w $adminpwd << EOF
dn: cn=user1,o=test,$basedn
changetype: modify
replace: description
description: Test User
EOF

echo "* Modifying sn of cn=user1,o=test,$basedn (adding attribute value)..."

ldapmodify -x -D $admindn -w $adminpwd << EOF
dn: cn=user1,o=test,$basedn
changetype: modify
add: sn
sn: Test
EOF

echo "* Modifying sn of cn=user1,o=test,$basedn (deleting attribute value)..."

ldapmodify -x -D $admindn -w $adminpwd << EOF
dn: cn=user1,o=test,$basedn
changetype: modify
delete: sn
sn: Test
EOF

echo "* Adding ou=sub,o=test,$basedn"

ldapadd -x -D $admindn -w $adminpwd << EOF
dn: ou=sub,o=test,$basedn
objectClass: organizationalUnit
ou: sub
EOF

echo "* Moving cn=user1,o=test,$basedn..."

ldapmodify -x -D $admindn -w $adminpwd << EOF
dn: cn=user1,o=test,$basedn
changetype: modrdn
newRDN: cn=user1
deleteoldrdn: 1
newSuperior: ou=sub,o=test,$basedn
EOF

echo "* Renaming cn=user1,o=test,$basedn..."

ldapmodify -x -D $admindn -w $adminpwd << EOF
dn: cn=user1,ou=sub,o=test,$basedn
changetype: modrdn
newRDN: cn=user2
deleteoldrdn: 1
EOF

echo "* Deleting entries"

ldapdelete -x -D $admindn -w $adminpwd cn=user2,ou=sub,o=test,$basedn
ldapdelete -x -D $admindn -w $adminpwd ou=sub,o=test,$basedn
ldapdelete -x -D $admindn -w $adminpwd o=test,$basedn

echo "RESULT changelog"

ldapsearch -x -D $admindn -w $adminpwd -b cn=changelog
