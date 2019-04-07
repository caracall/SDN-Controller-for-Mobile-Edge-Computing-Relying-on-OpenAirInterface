# SDN-Controller-for-Mobile-Edge-Computing-Relying-on-OpenAirInterface
This repository contains two python codes that play a big role in the traffic redirection in Mobile Edge Computing (MEC). RYU controller is in charge of the traffic redirection control. The main application is written in sdn_mec2_ryu.py, and the other code (Northbound_RYU.py) is responsible for the northbound API calls coming from the Mobile Edge Computing Platform Frontend to the RYU controller.

The main functionalities of sdn_mec2_ryu.py are:
- Initialize the variables from a configuration file
- Create a SQL database to store the redirection rules and their parameters, this will facilitate the control procedure held by the RYU controller
- Configure the default rules at the switch
- Design the Packet_IN logic when UE is up

The main functionality of Northbound_RYU.py is to add API endpoints to:
- Add a redirection rule to the database of the controller (SQL database)
- Delete a redirection rule from the database of the controller (SQL database)
- Display the redirection rules in the database of the controller (SQL database)
- Get the statistics of the flow rules existing in the OVS
