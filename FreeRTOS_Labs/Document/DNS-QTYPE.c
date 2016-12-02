其中QTYPE类型有

A               1 a host address

NS              2 an authoritative name server

MD              3 a mail destination (Obsolete - use MX)

MF              4 a mail forwarder (Obsolete - use MX)

CNAME           5 the canonical name for an alias

SOA             6 marks the start of a zone of authority

MB              7 a mailbox domain name (EXPERIMENTAL)

MG              8 a mail group member (EXPERIMENTAL)

MR              9 a mail rename domain name (EXPERIMENTAL)

NULL            10 a null RR (EXPERIMENTAL)

WKS             11 a well known service description

PTR             12 a domain name pointer

HINFO           13 host information

MINFO           14 mailbox or mail list information

MX              15 mail exchange

TXT             16 text strings

查询类型出现在问题字段中，查询类型是类型的一个超集，所有的类型都是可用的查询类型，其他查询类型如下：

AXFR            252 A request for a transfer of an entire zone

MAILB           253 A request for mailbox-related records (MB, MG or MR)

MAILA           254 A request for mail agent RRs (Obsolete - see MX)

*               255 A request for all records

 