// Vulnerable: VUL-CVE-2023-27772
IedConnection_connect(con, &error, hostname, tcpPort);

    if (error == IED_ERROR_OK) {


        /************************
...
            = ControlObjectClient_create("simpleIOGenericIO/GGIO1.SPCSO1", con);

        MmsValue* ctlVal = MmsValue_newBoolean(true);

...


        IedConnection_close(con);
