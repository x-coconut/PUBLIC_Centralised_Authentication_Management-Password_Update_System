# Copyright 2024 @x-coconut
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pika
from datetime import datetime
import random
import os
from rich.console import Console
import json
import base64
from ecies import decrypt
from cryptography.hazmat.primitives import serialization
from time import sleep

from libs.machines import (DeviceManagementException, SquidConnection, RDGConnection, KaliConnection)

# gets date and time
def get_time():
    return datetime.now().isoformat(sep=' ', timespec='seconds')
    
# declare the queues and exchanges
def setup_queues_and_exchange(channel):

    # declare exchange
    channel.exchange_declare(exchange='dlx_exchange', exchange_type='direct', durable=True)

    # declare queues
    channel.queue_declare(queue='main_queue', durable=True, arguments={
        'x-dead-letter-exchange': 'dlx_exchange',
        'x-dead-letter-routing-key': 'waiting_5_min'
    })

    channel.queue_declare(queue='waiting_5_min', durable=True, arguments={
        'x-message-ttl': 300000,  # TTL of 5 min
        'x-dead-letter-exchange': 'dlx_exchange',
        'x-dead-letter-routing-key': 'retry'
    })

    channel.queue_declare(queue='waiting_25_min', durable=True, arguments={
        'x-message-ttl': 1500000,  # TTL of 25 min
        'x-dead-letter-exchange': 'dlx_exchange',
        'x-dead-letter-routing-key': 'retry'
    })

    channel.queue_declare(queue='waiting_125_min', durable=True, arguments={
        'x-message-ttl': 7500000,  # TTL of 125 min (2h 5m)
        'x-dead-letter-exchange': 'dlx_exchange',
        'x-dead-letter-routing-key': 'retry'
    })

    channel.queue_declare(queue='waiting_625_min', durable=True, arguments={
        'x-message-ttl': 37500000,  # TTL of 625 min (10h 25m)
        'x-dead-letter-exchange': 'dlx_exchange',
        'x-dead-letter-routing-key': 'retry'
    })

    channel.queue_declare(queue='waiting_3125_min', durable=True, arguments={
        'x-message-ttl': 187500000,  # TTL of 3125 min (2d 4h 5m)
        'x-dead-letter-exchange': 'dlx_exchange',
        'x-dead-letter-routing-key': 'retry'
    })

    channel.queue_declare(queue='retry', durable=True)

    channel.queue_declare(queue='failed_messages', durable=True)

    # bind the queues to the exchange
    channel.queue_bind(exchange='dlx_exchange', queue='waiting_5_min', routing_key='waiting_5_min')
    channel.queue_bind(exchange='dlx_exchange', queue='waiting_25_min', routing_key='waiting_25_min')
    channel.queue_bind(exchange='dlx_exchange', queue='waiting_125_min', routing_key='waiting_125_min')
    channel.queue_bind(exchange='dlx_exchange', queue='waiting_625_min', routing_key='waiting_625_min')
    channel.queue_bind(exchange='dlx_exchange', queue='waiting_3125_min', routing_key='waiting_3125_min')
    channel.queue_bind(exchange='dlx_exchange', queue='retry', routing_key='retry')
    channel.queue_bind(exchange='dlx_exchange', queue='failed_messages', routing_key='failed_messages')

# update the users password in other systems
# error code 0 = no errors
# error code 1 = something went wrong
def process_message(body, number):

    error_code = 1
    c = Console()

    try: 
        # get data from the json
        data = json.loads(body)
        username = data.get('username')
        encryptedPassword = data.get('encryptedPassword')
        allowedIPs = data.get('allowedIPs')
    except:
        c.print(f"[red]{get_time()} [-] Error Converting Data to JSON for [bold]{username}[/bold][/red]")
        return error_code

    if encryptedPassword != "": # is set blank if theres an error

        # decrypt password
        password, error_code = decrypt_password(encryptedPassword, number)
        if error_code == 1:
            c.print(f"[red]{get_time()} [-] Error During Password Decryption for [bold]{username}[/bold][/red]")
            return error_code

        # update kali, squid, rdg
        error_code = update_machines(username, password, allowedIPs)
        if error_code == 1:
            c.print(f"[red]{get_time()} [-] Error Updating User on Machines for [bold]{username}[/bold][/red]")
            return error_code
        else:
            delete_file(number)
            error_code = 0
            return error_code
        
    else:
        error_code = 1
        c.print(f"[red]{get_time()} [-] Error During Password Encryption - Password for [bold]{username}[/bold] Updated on Keycloak Only[/red]")
        return error_code
      
# decrypts the encrypted password
# error code 0 = no errors
# error code 1 = something went wrong
def decrypt_password(encryptedPassword_b64, number):

    error_code = 1
    c = Console()

    encryptedPassword = base64.b64decode(encryptedPassword_b64)

    if number == "0":
        c.print(f"[red]{get_time()} [-] Decryption File Not Set [/red]")

    else:
        # get filepath for private key
        environmentVar = 'KEY_PATH'
        full_path = os.getenv(environmentVar)
        if full_path is None:
            c.print(f"[red]{get_time()} [-] Environment Variable [bold]{environmentVar}[/bold] is Not Set [/red]")
            return "", error_code
        directory = os.path.dirname(full_path)
        filepath = os.path.join(directory, f"private_key_{number}.txt")

        # check the file exists
        if os.path.exists(filepath):
            file = open(filepath, 'r')
            private_pem = file.read()
            file.close()

            # Load the private key from PEM format
            private_key = serialization.load_pem_private_key(
                private_pem.encode('utf-8'),
                password=None
            )

            # Extract the private key as bytes
            private_key_bytes = private_key.private_numbers().private_value.to_bytes(32, byteorder='big')

            # decrypt password
            password = decrypt(private_key_bytes, encryptedPassword).decode('utf-8')
            error_code = 0
            return password, error_code

        else:
            c.print(f"[red]{get_time()} [-] Decryption File Not Found: {filepath} [/red]")
            return "", error_code
            
# updates the username and password in kali, rdg, squid
# error code 0 = no errors
# error code 1 = something went wrong
def update_machines(username, password, allowedIPs): 

    error_code = 0
    c = Console()

    machines = [RDGConnection("10.135.160.126"), SquidConnection("10.135.160.10")]

    for ip in allowedIPs:

        # get last digit of ip address
        sections = ip.split('.')
        ip_section = int(sections[-1])
        ip_section -= 100 # the kali.py adds 100 back on

        for machine in machines + [KaliConnection(ip_section)]:
            attempts = 0
            while attempts < 3:
                try:

                    # get the correct machine name for kali machines
                    name = machine.name
                    if name.startswith("Kali"):
                        name = f"Kali-{ip}"

                    machine.updateCredential(username=username, password=password)
                except DeviceManagementException as e:
                    print(e.origException)
                    c.print(f"[yellow]{get_time()} [!] {e.mg} - Attempt [bold]{attempts+ 1}[/bold] [/yellow]")
                    sleep(2)
                else:
                    c.print(f"[green]{get_time()} [+] [bold]{username}[/bold] Successfully Updated on [bold]{name}[/bold] [/green]")
                    break
                attempts += 1
            if attempts >= 3:
                c.print(f"[red]{get_time()} [-] Failed to Update [bold]{username}[/bold] on [bold]{name}[/bold] - Moving On")
                error_code = 1
    
    return error_code

# save the encryption key
# error code 0 = no errors
# error code 1 = something went wrong
def save_key():

    c = Console()
    error_code = 1
    number = 0

    # get current private key
    try:
        environmentVar = 'KEY_PATH'
        full_path = os.getenv(environmentVar)
        if full_path is None:
            c.print(f"[red]{get_time()} [-] Environment Variable [bold]{environmentVar}[/bold] is Not Set [/red]")

        # retrieve pem private key from file
        file = open(full_path, 'r')
        private_pem = file.read()
        file.close()

        try:
            # generate a number to associate with decryption key
            num1 = random.randint(0,9)
            num2 = random.randint(0,9)
            num3 = random.randint(0,9)

            # get directory
            directory = os.path.dirname(full_path)
            filepath = os.path.join(directory, f"private_key_{num1}{num2}{num3}.txt")

            # check if file already exists
            if os.path.exists(filepath):
                number, error_code = save_key() # run again to get a file that doesn't already exist
                return number, error_code
            else:
                # save pem to file
                file = open(filepath, 'w')
                file.write(private_pem)
                file.close()

                error_code = 0
                number = str(num1) + str(num2) + str(num3)
                return number, error_code
        except:
            c.print(f"[red]{get_time()} [-] Error Saving to {filepath} [/red]")
            return number, error_code

    except:
        c.print(f"[red]{get_time()} [-] Error Accessing {full_path} [/red]")
        return number, error_code            

# deletes the private key once a message was processed successfully
def delete_file(number):
    
    c = Console()

    # delete the private key file
    try:
        environmentVar = 'KEY_PATH'
        full_path = os.getenv(environmentVar)
        if full_path is None:
            c.print(f"[red]{get_time()} [-] Environment Variable [bold]{environmentVar}[/bold] is Not Set [/red]")
        # get directory
        directory = os.path.dirname(full_path)
        filepath = os.path.join(directory, f"private_key_{number}.txt")

        # check if file already exists
        if os.path.exists(filepath):
            # delete file
            os.remove(filepath)
            return number
        else:
            c.print(f"[red]{get_time()} [-] File Not Deleted as Not Found: {filepath} [/red]")
        
    except:
        c.print(f"[red]{get_time()} [-] Error Deleting File {filepath} [/red]")
        
# messages arrive in main queue, the decryption key is saved in a file for later use
def callback_main_queue(channel):
    def _callback(ch, method, properties, body):

        c = Console()


        message = body.decode('utf-8')

        number, error_code = save_key()
        if error_code == 0:
            error_code = process_message(message, number)
            
            if error_code == 0:
                ch.basic_ack(delivery_tag=method.delivery_tag) # remove message from queue
            else:
                # remove message from queue
                ch.basic_ack(delivery_tag=method.delivery_tag)

                c.print(f"[yellow]{get_time()} [-] Failed to Proccess Message - Attempt [bold]1/4[/bold] {message} [/yellow]")

                # send message to waiting_5_min queue
                channel.basic_publish(
                    exchange='',
                    routing_key='waiting_5_min',
                    body=message,
                    properties=pika.BasicProperties(
                        delivery_mode=2,  # make message persistent
                        headers={
                        'decryption_number': number  # add private key file number to message header
                        }
                    )
                )

        else:
            # remove message from queue
            ch.basic_ack(delivery_tag=method.delivery_tag)

            # send message to waiting_5_min queue
            channel.basic_publish(
                exchange='',
                routing_key='waiting_5_min',
                body=message,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                        headers={
                        'decryption_number': number  # add private key file number to message header
                        }
                )
            )

    return _callback

def callback_retry_queue(channel):
    def _callback(ch, method, properties, body):
        c = Console()
        error_code = 1
        message = body.decode()
        headers = properties.headers

        # get info from headers
        decryption_number = headers.get('decryption_number', 'Not provided')
        retry_count = properties.headers.get('x-retry-count', 0) + 1

        error_code = process_message(message, decryption_number)

        if error_code == 0:
            ch.basic_ack(delivery_tag=method.delivery_tag) # remove message from queue
        else:

            # send mnessage to the appropriate waiting queue
            if retry_count <= 4:
                c.print(f"[yellow]{get_time()} [-] Failed to Proccess Message - Attempt [bold]{retry_count + 1}/6[/bold] {message} [/yellow]")

                next_queue = "waiting_" + str(5 ** (retry_count + 1)) + "_min"

                channel.basic_publish(
                    exchange='',
                    routing_key=next_queue,
                    body=message,
                    properties=pika.BasicProperties(
                        delivery_mode=2, # make message persistent
                        headers={'x-retry-count': retry_count, 
                                'decryption_number': decryption_number  # add private key file number to message header
                        }
                    )
                )

            else:
                c.print(f"[red]{get_time()} [-] Failed to Proccess Message - Attempt [bold]{retry_count + 1}/4[/bold] {message} [/red]")

                # Publish to failed_messages queue
                channel.basic_publish(
                    exchange='',
                    routing_key='failed_messages',
                    body=message,
                    properties=pika.BasicProperties(
                        delivery_mode=2,
                        headers={'x-retry-count': retry_count, 
                                'decryption_number': decryption_number  # add private key file number to message header
                        }
                    )
                )

            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

    return _callback

def main():
    c = Console()

    # connect to RabbitMQ
    try:
        credentials = pika.PlainCredentials('guest', 'guest') # UPDATE USERNAME, PASSWORD
        connection_params = pika.ConnectionParameters(
            host='192.168.43.128', # UPDATE IP
            port=5672,
            credentials=credentials
        )
        connection = pika.BlockingConnection(connection_params)
        channel = connection.channel()

        setup_queues_and_exchange(channel)

        channel.basic_consume(queue='main_queue', on_message_callback=callback_main_queue(channel))
        channel.basic_consume(queue='retry', on_message_callback=callback_retry_queue(channel))

        c.print(f"[green]{get_time()} [+] Waiting for Messages - Press CTRL+C to Exit [/green]")
        try:
            channel.start_consuming()
        except KeyboardInterrupt:
            c.print(f"\n[red]{get_time()} [-] Interrupted[/red]")
        except pika.exceptions.AMQPConnectionError as e:
            c.print(f"\n[red]{get_time()} [-] Connection Error: {e} [/red]")
        finally:
            try:
                connection.close()
            except pika.exceptions.ConnectionWrongStateError:
                c.print(f"\n[red]{get_time()} [-] Connection was Already Closed or in an Incorrect State [/red]")
    except:
        c.print(f"[red]{get_time()} [-] Failed to Connect to RabbitMQ Server [/red]")

if __name__ == "__main__":
    main()
