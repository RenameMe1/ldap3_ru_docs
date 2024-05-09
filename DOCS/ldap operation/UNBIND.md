---
tags:
  - ldap3
  - python
---
# Операция Unbind

Как указано в RFC4511 операция **Unbind** должна быть задумана как операция "disconnect". Ее имя (так же как и у его коллеги [[BIND]]) имеет имеет исторические причины.  

[[BIND]] и [[UNBIND]] не симметричные операции. Фактически, когда вы открываете подключение к LDAP серверу, вы уже привязаны в состоянии анонимного подключения. Что именно это означает определяется серверной реализацией, не протоколом. Когда вы выполняете [[UNBIND]] операцию, вы на самом деле запрашиваете у сервера конец пользовательской сессии и закрытие сокета коммуникации. 

Так что совершенно законно открыть подключение к ldap серверу,  выполнить некоторые операций в анонимном статусе и использовать [[UNBIND]] для закрытия сессии.

В библиотеке [[ldap3]] сигнатура для операции [[UNBIND|Unbind]]:

```python
def unbind(
		self,
		controls=None
):
```

- controls: дополнительные регуляторы для отправки в запросе

Метод [[UNBIND]] всегда возвращает `True`.

Вы выполняете операцию [[UNBIND]] как в следующем примере (используя стандартную синхронную стратегию):

``` python
# Иморт классов и констант
from ldap3 import Server, Connection, ALL

# Определение небезопасного LDAP сервера, запрос информации о DSE и схеме
s = Server('servername', get_info=ALL)

# Определение подключения
c = Connecton(s, user='user_dn', password='user_password')

# Выполнение некоторых LDAP операций
...

# Выполнение операции Unbind
c.unbind()
```

Запрос [[UNBIND]] довольно своеобразный в протоколе LDAPv3. Нет подтверждения от сервера, нет ответов совсем. Это просто закрытие сессии пользователя и закрытие сокета. Библиотека [[ldap3]] проверяет успех этой операции завершая работу сокета на обоих направлениях связи и затем закрывает сокет.

Вы можете проверить, если сокет был закрыт запросив атрибут *closed*  объекта [[Connection|connection]]

# Уведомление об отключении (Notice of Disconnection)

Обычно связи между клиентом и сервером инициируются клиентом. Есть только один случай где LDAP сервер отправляет незапрашиваемое сообщение: Уведомление об отключении (Notice of Disconnection). Это сообщение выдается сервером как оповещение, когда сервер вот-вот остановится. Как только сообщение отправлено, сервер не ожидает ответа, закрывает сокет и выключается. Обратите внимание, что это уведомление не используется как ответ на [[UNBIND]] запрос клиента.

Когда библиотека [[ldap3]] получает Уведомление об отключении, она пытается элегантно закрыть сокет и после вызвать исключение `LDAPSessionTerminatedByServer`. При асинхронных стратегиях исключение вызывается незамедлительно, при синхронных стратегиях исключение вызывается, когда вы пытаетесь отправить данные через сокет. 

# Расширенное логирование

Для получения представления о том, что происходит при вашем выполнении операции [[UNBIND]] это расширенный лог из сессии OpenLdap сервера из Windows клиента: 

``` log
# Инициализация:
INFO:ldap3:ldap3 library initialized - logging emitted with loglevel set to DEBUG - available detail levels are: OFF, ERROR, BASIC, PROTOCOL, NETWORK, EXTENDED
DEBUG:ldap3:ERROR:detail level set to EXTENDED
DEBUG:ldap3:BASIC:instantiated Server: <Server(host='openldap', port=389, use_ssl=False, get_info='NO_INFO')>
DEBUG:ldap3:BASIC:instantiated Usage object
DEBUG:ldap3:BASIC:instantiated <SyncStrategy>: <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <no socket> - tls not started - not listening - No strategy - async - real DSA - not pooled - cannot stream output>
DEBUG:ldap3:BASIC:instantiated Connection: <Connection(server=Server(host='openldap', port=389, use_ssl=False, get_info='NO_INFO'), user='cn=admin,o=test', password='password', auto_bind='NONE', version=3, authentication='SIMPLE', client_strategy='SYNC', auto_referrals=True, check_names=True, collect_usage=True, read_only=False, lazy=False, raise_exceptions=False)>
DEBUG:ldap3:NETWORK:opening connection for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <no socket> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:reset usage metrics
DEBUG:ldap3:BASIC:start collecting usage metrics
DEBUG:ldap3:BASIC:address for <ldap://openldap:389 - cleartext> resolved as <[<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]>
DEBUG:ldap3:BASIC:address for <ldap://openldap:389 - cleartext> resolved as <[<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]>
DEBUG:ldap3:BASIC:obtained candidate address for <ldap://openldap:389 - cleartext>: <[<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]> with mode IP_V6_PREFERRED
DEBUG:ldap3:BASIC:obtained candidate address for <ldap://openldap:389 - cleartext>: <[<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]> with mode IP_V6_PREFERRED

# Открытие подключения (попытки IPv6 затем IPv4):

DEBUG:ldap3:BASIC:try to open candidate address [<AddressFamily.AF_INET6: 23>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('fe80::215:5dff:fe8f:2f0d%20', 389, 0, 20)]
DEBUG:ldap3:ERROR:<socket connection error: [WinError 10061] No connection could be made because the target machine actively refused it.> for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <local: [::]:49610 - remote: [None]:None> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:try to open candidate address [<AddressFamily.AF_INET: 2>, <SocketKind.SOCK_STREAM: 1>, 6, '', ('192.168.137.104', 389)]
DEBUG:ldap3:NETWORK:connection open for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:BASIC:refreshing server info for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>

# Выполнение Unbind операции:

DEBUG:ldap3:BASIC:start UNBIND operation via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:UNBIND request sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:PROTOCOL:new message id <1> generated
DEBUG:ldap3:NETWORK:sending 1 ldap message for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:EXTENDED:ldap message sent via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>:
>>LDAPMessage:
>> messageID=1
>> protocolOp=ProtocolOp:
>>  unbindRequest=b''
DEBUG:ldap3:NETWORK:sent 7 bytes via <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:closing connection for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - open - <local: 192.168.137.1:49291 - remote: 192.168.137.104:389> - tls not started - listening - SyncStrategy>
DEBUG:ldap3:NETWORK:connection closed for <ldap://openldap:389 - cleartext - user: cn=admin,o=test - unbound - closed - <no socket> - tls not started - not listening - SyncStrategy>
DEBUG:ldap3:BASIC:stop collecting usage metrics
DEBUG:ldap3:BASIC:done UNBIND operation, result <True>
```

Это используемые метрики данной сессии:

``` info 
Connection Usage:
  Time: [elapsed:        0:00:01.030738]
    Initial start time:  2015-06-04T17:01:43.431465
    Open socket time:    2015-06-04T17:01:43.431465
    Close socket time:   2015-06-04T17:01:44.462203
  Server:
    Servers from pool:   0
    Sockets open:        1
    Sockets closed:      1
    Sockets wrapped:     0
  Bytes:                 7
    Transmitted:         7
    Received:            0
  Messages:              1
    Transmitted:         1
    Received:            0
  Operations:            1
    Abandon:             0
    Bind:                0
    Add:                 0
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

Как мы можем видеть есть только одна операция [[UNBIND]]. Один сокет был открыт и закрыт. Все коммуникационные потоки приняли 7 байт в 1 LDAP сообщении и сервер ничего не отправил обратно.