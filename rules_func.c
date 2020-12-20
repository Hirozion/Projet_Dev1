#include "populate.h"


void rule_matcher(Rule *rules_ds, ETHER_Frame *frame, int count)
{	
	for (int i = 0 ; i < count ; i ++)
	{
		switch(frame->data.ip_protocol) //TCP IMCP UDP 
		{
			case 6: // TCP_PROTOCOL
				if(frame->data.data.destination_port == atoi(rules_ds[i].port_destination)) //TCP msg
					generate_syslog(rules_ds[i].ids_option.key);
				else if(search_web_content((char*)rules_ds[i].ids_option.values,(char*)frame->data.data.data))
					generate_syslog(rules_ds[i].ids_option.key);			
				else
					break;

			case 17: //UDP_PROTOCOL
				if(frame->data.data_UDP.destination_port == atoi(rules_ds[i].port_destination))
					generate_syslog(rules_ds[i].ids_option.key);
				break;

			case 1: //ICMP_PROTOCOL
				if(strcmp(frame->data.source_ip,rules_ds[i].source_IP) == 0)
					generate_syslog(rules_ds[i].ids_option.key);
				break;
		}
		if(frame->data.data.destination_port == 21)
			{
				char *protocol = "ftp";
				if(strcmp(rules_ds[i].protocol,protocol) == 0)
					generate_syslog(rules_ds[i].ids_option.key);
			}					
	}
	if(frame->data.data.destination_port == 443 && strstr((char*)frame->data.data.data,"GET ") == NULL)
		printf("ENCRYPTION DETECTED\n");
}


void read_rules(FILE * file, Rule *rules_ds, int count)
{
	char texte[256];
	for (int i = 0; i < count; i++)
	{
		fgets(texte,256,file);
		//séparer la chaine en 2 header + option
		char find = '(';
		const char *ptr = strchr(texte,find);
		int index = ptr - texte; //trouver index pour separer header et option
	    char rules_header[100];	// alert http any any -> any any
	    char rules_options[100]; //(msg:"shell attack"; content:"malware.exe";)

	    memset(rules_header,'\0',sizeof(rules_header));
        strncpy(rules_header,texte,index); //strncpy(<destination>,<source>,<n>)

	    memset(rules_options,'\0',sizeof(rules_header));
	    strncpy(rules_options,texte + index,strlen(texte));

		rules_ds[i].ids_option.key = (char*)calloc(100,sizeof(char)); // hésite sizeof(char) * strlen(rules_option)
		rules_ds[i].ids_option.values = (char*)calloc(100,sizeof(char)); // malloc(sizeof(rules_option))

		sscanf(rules_header,"%s %s %s %s %s %s %s",rules_ds[i].type, rules_ds[i].protocol, rules_ds[i].source_IP,
	    	rules_ds[i].port_source, rules_ds[i].direction, rules_ds[i].destination_IP, rules_ds[i].port_destination);

	    const char *delimiter = ("();");

        char *token = strtok(rules_options,delimiter);
        strcpy(rules_ds[i].ids_option.key,token);

        token = strtok(NULL,delimiter);
        strcpy(rules_ds[i].ids_option.values,token);
    	
	}
}

void free_memory(Rule *rules_ds, int count)
{
	for (int i = 0; i < count; i ++)
	{
		free(rules_ds[i].ids_option.key);
		free(rules_ds[i].ids_option.values);
	}
	free(rules_ds);
}
int count_lines_from_file(FILE *fic)
{
	int c = 0;
	int lines = 0;
	while(!feof(fic))
	{
		c = fgetc(fic);
		if(c == '\n')
			lines ++;
	}
	rewind(fic); // remetre le curseur au debut du fichier 
	return lines;
}
void generate_syslog(char *log_msg)
{
	openlog("-- IDS ALERT --  ",LOG_PID,LOG_USER);
	syslog(LOG_INFO,log_msg);
}

Bool search_web_content(char *values, char *data)
{	
	if(strlen(values) > 5) 
	{
		char find[100];
		strcpy(find,values);

		const char *delimiter = ("\": ");
   		char *token = strtok(find,delimiter); //content
   		token = strtok(NULL,delimiter);  // malware.exe
   		if (strstr(data,token) != NULL)
      		return true;   		
	}
	return false;
}