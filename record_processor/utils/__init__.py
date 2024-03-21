# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.


import zipfile
import json
import os


def unzip_and_read_file(file_path: str) -> str:
    """
    Unzip the file and read the content of the extracted file.
    file_path: the path of the pending zip file.
    return: the content of the extracted file.
    """
    extracted_file = unzip_file(file_path)
    with open(extracted_file, 'r', encoding='utf-8') as file:
        content = file.read()
    return content


def unzip_file(zip_file_path: str) -> str:
    """
    Unzip the file and return the path of the extracted file.
    zip_file_path: the path of the pending zip file.
    return: the path of the extracted file.
    """
    folder_name = os.path.splitext(zip_file_path)[0]

    # Create the directory if it doesn't exist
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    # Extract the contents of the ZIP file into the directory
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(folder_name)

    extracted_file = os.path.join(folder_name, os.listdir(folder_name)[0])
    return extracted_file


def save_to_json(data: dict, output_file_path: str):
    """
    Save the data to a JSON file.
    data: the data to save.
    output_file_path: the path of the output file.
    """

    # Extract the directory path from the file path
    directory = os.path.dirname(output_file_path)

    # Check if the directory exists, if not, create it
    if not os.path.exists(directory):
        os.makedirs(directory)

    with open(output_file_path, 'w') as file:
        json.dump(data, file, indent=4)
