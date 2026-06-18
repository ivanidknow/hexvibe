// Vulnerable: VUL-CVE-2021-41039
/* Check for duplicates */
tail = p->next;
while(tail){
        if(p->identifier == tail->identifier
                        && p->identifier != MQTT_PROP_USER_PROPERTY){

                return MOSQ_ERR_DUPLICATE_PROPERTY;
        }
        tail = tail->next;
}
