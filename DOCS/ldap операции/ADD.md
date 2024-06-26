---
tags:
  - ldap3
  - python
---
# Операция ADD

Операция [[ADD]] позволяет клиентам запросить добавление записи в LDAP каталог. Операция [[ADD]] используется только для новых записей, то есть distinguished-name должно ссылаться на не существующий объект, но родительский объекты должны существовать. Для примера если вы пытаетесь добавить запись с DN (от _distinguished name_) `cn=user1,ou=users,o=company` то, `company` и `users` контейнеры должны уже быть представлены в каталоге, но объект `user1` не должен существовать.  

Для выполнения операции [[ADD]] вы должны указать DN (от _distinguished name_) новой записи и список атрибутов для добавления. 

В библиотеке  [[ldap3]] сигнатура для операции ADD:

``` python
def add(
		self,
		dn,
		object_class=None,
		attributes=None,
		controls=None
		)
```

- dn: Отличительное имя объекта для добавления
- object_class: Имя класса атрибута для добавления, может быть строкой содержащей одиночное значение или список строк
- attributes: Словарь в формате `{'attr1': 'val1', 'attr2': 'val2', ...}` или `{‘attr1’: [‘val1’, ‘val2’, …], …}` для многозначных атрибутов
- controls: дополнительные регуляторы для отправки с запросом

Для синхронных стратегий метод [[ADD]]  возвращает `True` если операция была успешно, возвращает `False` в случае ошибок. В этом случае вы можете проверит атрибут `result` объекта [[Connection|connection]] для получения описания ошибки.

Для асинхронных стратегий метод [[ADD]] возвращает идентификатор сообщения операции. Вы можете получить результат операции с помощью метода `get_response(message_id)` объекта [[Connection|connection]]. Если вы используете  параметр `get_request=True` вы получаете обратно словарь запроса. 

Параметр `object_class` - ярлык для указания последовательности объектов классов. Вы можете указывать объекты классов в параметре `attributes` тоже.

Если вы пытаетесь добавить атрибут с пустым значением или многозначные атрибуты со всеми пустыми значениями, атрибут не будет создан, потому-что протокол LDAP не поддерживает значения NULL.

Вы выполняете операцию [[ADD]] как в следующем примере (используя стандартную синхронную стратегию):

``` python
# испорт классов и констант
from ldap3 import Server, Connection, ALL

# Определение не безопасного LDAP сервера, запрашивающего DSE и схему
s = Server('servername', get_info=ALL) 

# Определение подключения
c = Connection(s, user='user_dn', password='user_password')

# Выполнение операции Add
c.add('cn=user1,ou=users,o=company', ['inetOrgPerson', 'posixGroup', 'top'], {'sn': 'user_sn', 'gidNumber': 0})
# Аналогично
c.add('cn=user1,ou=users,o=company', attributes={'objectClass':  ['inetOrgPerson', 'posixGroup', 'top'], 'sn': 'user_sn', gidNumber: 0})

print(c.result)

# Закрытие подключения

c.unbind()
```

Очевидно, вы должны следовать всем правилам и  ограничениям указанным схеме LDAP сервера.  Кроме того, вы не можете указывать какие-либо рабочие атрибуты или любой атрибут определенный в схеме флагом `NO-USER-MODIFICATION` или операция завершится неудачей.  

# Расширенное логирование

To get an idea of what’s happening when you perform an Add operation this is the extended log from a session to an OpenLdap server from a Windows client with dual stack IP:

``` log
# Инициализация:

INFO:ldap3:ldap3 library initialized - logging emitted with loglevel set to DEBUG - available detail levels are: OFF, ERROR, BASIC, PROTOCOL, NETWORK, EXTENDED
DEBUG:ldap3:ERROR:detail level set to EXTENDED
DEBUG:ldap3:BASIC:instantiated Server: <Server(host='openldap', port=389, use_ssl=False, get_info='NO_INFO')>
DEBUG:ldap3:BASIC:instantiated Usage object
DEBUG:ldap3:BASIC:instantiated <SyncStrategy>: <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <no socket> - tls not started - not listening - No strategy - async - real DSA - not pooled - cannot stream output>
DEBUG:ldap3:BASIC:instantiated Connection: <Connection(server=Server(host='openldap', port=389, use_ssl=False, get_info='NO_INFO'), user='cn=admin,o=test', password='<stripped 8 characters of sensitive data>', auto_bind='NONE', version=3, authentication='SIMPLE', client_strategy='SYNC', auto_referrals=True, check_names=True, collect_usage=True, read_only=False, lazy=False, raise_exceptions=False)>
DEBUG:ldap3:NETWORK:opening connection for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <no socket> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:reset usage metrics
DEBUG:ldap3:BASIC:start collecting usage metrics
DEBUG:ldap3:BASIC:address for <ldap://openldap:389 - cleartext> resolved as <[<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]>
DEBUG:ldap3:BASIC:address for <ldap://openldap:389 - cleartext> resolved as <[<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]>
DEBUG:ldap3:BASIC:obtained candidate address for <ldap://openldap:389 - cleartext>: <[<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]> with mode IP_V6_PREFERRED
DEBUG:ldap3:BASIC:obtained candidate address for <ldap://openldap:389 - cleartext>: <[<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]> with mode IP_V6_PREFERRED

# Открытие подключения (попытки IPv6 затем IPv4):

DEBUG:ldap3:BASIC:try to open candidate address [<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]
DEBUG:ldap3:ERROR:<socket connection error: [WinError 10061] No connection could be made because the target machine actively refused it.> for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <local: [::]:50396 - remote: [None]:None> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:try to open candidate address [<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]
DEBUG:ldap3:NETWORK:connection open for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:refreshing server info for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>

# Аутентификация в LDAP сервере с использованием метода Simple Bind:

DEBUG:ldap3:BASIC:start BIND operation via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:performing simple BIND for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:simple BIND request <{'authentication': {'simple': '<stripped 8 characters of sensitive data>', 'sasl': None}, 'name': 'cn=admin,o=test', 'version': 3}> sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:new message id <1> generated
DEBUG:ldap3:NETWORK:sending 1 ldap message for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
>>LDAPMessage:
>> messageID=1
>> protocolOp=ProtocolOp:
>>  bindRequest=BindRequest:
>>   version=3
>>   name=b'cn=admin,o=test'
>>   authentication=AuthenticationChoice:
>>    simple=b'<stripped 8 characters of sensitive data>'
DEBUG:ldap3:NETWORK:sent 37 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 14 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 1 ldap messages via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
<<LDAPMessage:
<< messageID=1
<< protocolOp=ProtocolOp:
<<  bindResponse=BindResponse:
<<   resultCode='success'
<<   matchedDN=b''
<<   diagnosticMessage=b''
DEBUG:ldap3:PROTOCOL:BIND response <{'referrals': None, 'type': 'bindResponse', 'result': 0, 'message': '', 'dn': '', 'saslCreds': None, 'description': 'success'}> received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:refreshing server info for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:done BIND operation, result <True>

# Выполнение операции Add:

DEBUG:ldap3:BASIC:start ADD operation via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:ADD request <{'entry': 'cn=user1,o=test', 'attributes': {'gidNumber': ['0'], 'sn': ['user_sn'], 'objectClass': ['inetOrgPerson', 'posixGroup', 'top']}}> sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:new message id <2> generated
DEBUG:ldap3:NETWORK:sending 1 ldap message for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
>>LDAPMessage:
>> messageID=2
>> protocolOp=ProtocolOp:
>>  addRequest=AddRequest:
>>   entry=b'cn=user1,o=test'
>>   attributes=AttributeList:
>>    Attribute:
>>     type=b'gidNumber'
>>     vals=ValsAtLeast1:
>>      b'0'
>>    Attribute:
>>     type=b'sn'
>>     vals=ValsAtLeast1:
>>      b'user_sn'
>>    Attribute:
>>     type=b'objectClass'
>>     vals=ValsAtLeast1:
>>      b'inetOrgPerson'      b'posixGroup'      b'top'
DEBUG:ldap3:NETWORK:sent 110 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 14 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:received 1 ldap messages via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
<<LDAPMessage:
<< messageID=2
<< protocolOp=ProtocolOp:
<<  addResponse=AddResponse:
<<   resultCode='entryAlreadyExists'
<<   matchedDN=b''
<<   diagnosticMessage=b''
DEBUG:ldap3:PROTOCOL:ADD response <[{'referrals': None, 'type': 'addResponse', 'result': 68, 'message': '', 'dn': '', 'description': 'entryAlreadyExists'}]> received via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:done ADD operation, result <False>

# Закрытие подключения (через операцию Unbind):

DEBUG:ldap3:BASIC:start UNBIND operation via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:UNBIND request sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:new message id <3> generated
DEBUG:ldap3:NETWORK:sending 1 ldap message for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
>>LDAPMessage:
>> messageID=3
>> protocolOp=ProtocolOp:
>>  unbindRequest=b''
DEBUG:ldap3:NETWORK:sent 7 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:closing connection for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - open - <local: 192.168.137.1:50397 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:connection closed for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - bound - closed - <no socket> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:stop collecting usage metrics
DEBUG:ldap3:BASIC:done UNBIND operation, result <True>
```

Это используемые метрики данной сесии:

``` config
Connection Usage:
  Time: [elapsed:        0:00:01.043802]
    Initial start time:  2015-06-05T23:38:29.505383
    Open socket time:    2015-06-05T23:38:29.505383
    Close socket time:   2015-06-05T23:38:30.549185
  Server:
    Servers from pool:   0
    Sockets open:        1
    Sockets closed:      1
    Sockets wrapped:     0
  Bytes:                 182
    Transmitted:         154
    Received:            28
  Messages:              5
    Transmitted:         3
    Received:            2
  Operations:            3
    Abandon:             0
    Bind:                1
    Add:                 1
    Compare:             0
    Delete:              0
    Extended:            0
    Modify:              0
    ModifyDn:            0
    Search:              0
    Unbind:              1
  Referrals:
    Received:            0
    Followed:            0
  Restartable tries:     0
    Failed restarts:     0
    Successful restarts: 0
    ```