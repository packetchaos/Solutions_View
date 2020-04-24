# Solutions View
A small web application built on Flask and deployed in a Docker container.

It pulls Remediation information from Tenable.sc and Displays it on the 
application.  You can then drill down into each vulnerability and host 
to get more information

# Download the Repository
Clone the repository to your local machine

    git clone https://github.com/packetchaos/Solutions_View.git

# Update the Script
You will need to update the script SC_newHost.py with your SC credentials

# Set User data

    hostname = "<your T.sc IP address>"
    username = "<your User Name>"
    password = "<your password>"

# Build the docker container
    docker build -t silentninja/solutions:latest .

# Run the docker container
    docker run -d -p 5001:5001 silentninja/solutions:latest
