#install whois module 
    pip install python-whois

#install nmap module 
    pip install python-nmap

#install openai module 
    pip install openai_secret_manager



To get API credentials for the given code, you need to follow these steps:

    Go to the OpenAI website and sign up for an account if you haven't already.
    Once you have signed up and logged in, go to the "API Keys" page.
    Click on the "Generate New Key" button to generate a new API key.
    Give your key a name and select the appropriate permissions.
    Copy the API key and use it in the chatgpt_key variable in the code, replacing the openai_secret_manager.get_secret("openai")["api_key"] line.

Note that you also need to have the openai_secret_manager Python package installed to use the get_secret function. You can install it using pip install openai_secret_manager.

