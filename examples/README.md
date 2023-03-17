# Example Scripts

_Original source: https://developer.dataplatform.knmi.nl/example-scripts_

This page contains multiple example scripts that are written in [Python 3.8](https://docs.python.org/3.8/). Each example consists of a description, and the code listing.

Each Python3 script requires the following external Python packages installed on the system:

*   `requests`;

We refer to the [Python3 documentation](https://docs.python.org/3/installing/index.html#installing-python-modules) for instructions on how to install Python packages.

## Retrieving datasets

To retrieve datasets, follow these steps:

1.  Create an account on our Developer Portal, and use this account to request an API key with permissions to list and get files from a dataset, or use the anonymous API key listed in the [Obtain an API key](get-started#obtain-an-api-key ) section;
2.  List the files in a dataset;
3.  Retrieve a download url for a file in the dataset;
4.  Download the file using the retrieved url.

### List first page of files in the `Actuele10mindataKNMIstations` dataset

    curl --location --request GET \
    "https://api.dataplatform.knmi.nl/open-data/v1/datasets/Actuele10mindataKNMIstations/versions/2/files" \
    --header "Authorization: <API_KEY>"

The default page size for listing files is 10.

### List 15 files in `Actuele10mindataKNMIstations` dataset

    curl --location --request GET -G \
    "https://api.dataplatform.knmi.nl/open-data/v1/datasets/Actuele10mindataKNMIstations/versions/2/files" \
    -d maxKeys=15 \
    --header "Authorization: <API_KEY>"

### List the first 15 files ordered alphabetically after the given value for `startAfterFileName`

    curl --location --request GET -G \
    "https://api.dataplatform.knmi.nl/open-data/v1/datasets/Actuele10mindataKNMIstations/versions/2/files" \
    -d maxKeys=15 \
    -d startAfterFilename=KMDS__OPER_P___10M_OBS_L2_202007162330.nc \
    --header "Authorization: <API_KEY>"

### Listing the first 10 files of today and retrieving the first one

    import logging
    import sys
    from datetime import datetime

    import requests

    logging.basicConfig()
    logger = logging.getLogger(__name__)
    logger.setLevel("INFO")

    api_url = "https://api.dataplatform.knmi.nl/open-data"
    api_version = "v1"

    def main():
        # Parameters
        api_key = "<API_KEY>"
        dataset_name = "Actuele10mindataKNMIstations"
        dataset_version = "2"
        max_keys = "10"

        # Use list files request to request first 10 files of the day.
        timestamp = datetime.utcnow().date().strftime("%Y%m%d")
        start_after_filename_prefix = f"KMDS__OPER_P___10M_OBS_L2_{timestamp}"
        list_files_response = requests.get(
            f"{api_url}/{api_version}/datasets/{dataset_name}/versions/{dataset_version}/files",
            headers={"Authorization": api_key},
            params={"maxKeys": max_keys, "startAfterFilename": start_after_filename_prefix},
        )
        list_files = list_files_response.json()

        logger.info(f"List files response:\n{list_files}")
        dataset_files = list_files.get("files")

        # Retrieve first file in the list files response
        filename = dataset_files[0].get("filename")
        logger.info(f"Retrieve file with name: {filename}")
        endpoint = f"{api_url}/{api_version}/datasets/{dataset_name}/versions/{dataset_version}/files/{filename}/url"
        get_file_response = requests.get(endpoint, headers={"Authorization": api_key})
        if get_file_response.status_code != 200:
            logger.error("Unable to retrieve download url for file")
            logger.error(get_file_response.text)
            sys.exit(1)

        download_url = get_file_response.json().get("temporaryDownloadUrl")
        download_file_from_temporary_download_url(download_url, filename)

    def download_file_from_temporary_download_url(download_url, filename):
        try:
            with requests.get(download_url, stream=True) as r:
                r.raise_for_status()
                with open(filename, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
        except Exception:
            logger.exception("Unable to download file using download URL")
            sys.exit(1)

        logger.info(f"Successfully downloaded dataset file to {filename}")

    if __name__ == "__main__":
        main()

### Retrieving the file from one hour ago and logging deprecation

    import logging
    import os
    import sys
    from datetime import datetime
    from datetime import timedelta

    import requests

    logging.basicConfig()
    logger = logging.getLogger(__name__)
    logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))

    api_url = "https://api.dataplatform.knmi.nl/open-data"
    api_version = "v1"

    def main():
        # Parameters
        api_key = "<API_KEY>"
        dataset_name = "Actuele10mindataKNMIstations"
        dataset_version = "2"

        # Use get file to retrieve a file from one hour ago.
        # Filename format for this dataset equals KMDS__OPER_P___10M_OBS_L2_YYYYMMDDHHMM.nc,
        # where the minutes are increased in steps of 10.
        timestamp_now = datetime.utcnow()
        timestamp_one_hour_ago = timestamp_now - timedelta(hours=1) - timedelta(minutes=timestamp_now.minute % 10)
        filename = f"KMDS__OPER_P___10M_OBS_L2_{timestamp_one_hour_ago.strftime('%Y%m%d%H%M')}.nc"

        logger.debug(f"Current time: {timestamp_now}")
        logger.debug(f"One hour ago: {timestamp_one_hour_ago}")
        logger.debug(f"Dataset file to download: {filename}")

        endpoint = f"{api_url}/{api_version}/datasets/{dataset_name}/versions/{dataset_version}/files/{filename}/url"
        get_file_response = requests.get(endpoint, headers={"Authorization": api_key})

        if get_file_response.status_code != 200:
            logger.error("Unable to retrieve download url for file")
            logger.error(get_file_response.text)
            sys.exit(1)

        logger.info(f"Successfully retrieved temporary download URL for dataset file {filename}")

        download_url = get_file_response.json().get("temporaryDownloadUrl")
        # Check logging for deprecation
        if "X-KNMI-Deprecation" in get_file_response.headers:
            deprecation_message = get_file_response.headers.get("X-KNMI-Deprecation")
            logger.warning(f"Deprecation message: {deprecation_message}")

        download_file_from_temporary_download_url(download_url, filename)

    def download_file_from_temporary_download_url(download_url, filename):
        try:
            with requests.get(download_url, stream=True) as r:
                r.raise_for_status()
                with open(filename, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
        except Exception:
            logger.exception("Unable to download file using download URL")
            sys.exit(1)

        logger.info(f"Successfully downloaded dataset file to {filename}")

    if __name__ == "__main__":
        main()

### Complete Dataset Download

Once you have obtained a dedicated API key to download a complete dataset, you are ready to download the corresponding dataset files. To retrieve these files efficiently, we provide an example script. This script shows how to download the complete `EV24/2` dataset. The structure of this script is the same regardless the dataset you want to download.

Make sure to change `download_directory` to an existing empty directory.

    import asyncio
    import logging
    import os
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path
    from typing import Any
    from typing import Dict
    from typing import List
    from typing import Tuple

    import requests
    from requests import Session

    logging.basicConfig()
    logger = logging.getLogger(__name__)
    logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))

    def download_dataset_file(
        session: Session,
        base_url: str,
        dataset_name: str,
        dataset_version: str,
        filename: str,
        directory: str,
        overwrite: bool,
    ) -> Tuple[bool, str]:
        # if a file from this dataset already exists, skip downloading it.
        file_path = Path(directory, filename).resolve()
        if not overwrite and file_path.exists():
            logger.info(f"Dataset file '{filename}' was already downloaded.")
            return True, filename

        endpoint = f"{base_url}/datasets/{dataset_name}/versions/{dataset_version}/files/{filename}/url"
        get_file_response = session.get(endpoint)

        # retrieve download URL for dataset file
        if get_file_response.status_code != 200:
            logger.warning(f"Unable to get file: {filename}")
            logger.warning(get_file_response.content)
            return False, filename

        # use download URL to GET dataset file. We don't need to set the 'Authorization' header,
        # The presigned download URL already has permissions to GET the file contents
        download_url = get_file_response.json().get("temporaryDownloadUrl")
        return download_file_from_temporary_download_url(download_url, directory, filename)

    def download_file_from_temporary_download_url(download_url, directory, filename):
        try:
            with requests.get(download_url, stream=True) as r:
                r.raise_for_status()
                with open(f"{directory}/{filename}", "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
        except Exception:
            logger.exception("Unable to download file using download URL")
            return False, filename

        logger.info(f"Downloaded dataset file '{filename}'")
        return True, filename

    def list_dataset_files(
        session: Session,
        base_url: str,
        dataset_name: str,
        dataset_version: str,
        params: Dict[str, str],
    ) -> Tuple[List[str], Dict[str, Any]]:
        logger.info(f"Retrieve dataset files with query params: {params}")

        list_files_endpoint = f"{base_url}/datasets/{dataset_name}/versions/{dataset_version}/files"
        list_files_response = session.get(list_files_endpoint, params=params)

        if list_files_response.status_code != 200:
            raise Exception("Unable to list initial dataset files")

        try:
            list_files_response_json = list_files_response.json()
            dataset_files = list_files_response_json.get("files")
            dataset_filenames = list(map(lambda x: x.get("filename"), dataset_files))
            return dataset_filenames, list_files_response_json
        except Exception as e:
            logger.exception(e)
            raise Exception(e)

    def get_max_worker_count(filesizes):
        size_for_threading = 10_000_000  # 10 MB
        average = sum(filesizes) / len(filesizes)
        # to prevent downloading multiple half files in case of a network failure with big files
        if average > size_for_threading:
            threads = 1
        else:
            threads = 10
        return threads

    async def main():
        api_key = "<API_KEY>"
        dataset_name = "EV24"
        dataset_version = "2"
        base_url = "https://api.dataplatform.knmi.nl/open-data/v1"
        # When set to True, if a file with the same name exists the output is written over the file.
        # To prevent unnecessary bandwidth usage, leave it set to False.
        overwrite = False

        download_directory = "./dataset-download"

        # Make sure to send the API key with every HTTP request
        session = requests.Session()
        session.headers.update({"Authorization": api_key})

        # Verify that the download directory exists
        if not Path(download_directory).is_dir() or not Path(download_directory).exists():
            raise Exception(f"Invalid or non-existing directory: {download_directory}")

        filenames = []

        start_after_filename = " "
        max_keys = 500

        file_sizes = []
        # Use the API to get a list of all dataset filenames
        while True:
            # Retrieve dataset files after given filename
            dataset_filenames, response_json = list_dataset_files(
                session,
                base_url,
                dataset_name,
                dataset_version,
                {"maxKeys": f"{max_keys}", "startAfterFilename": start_after_filename},
            )
            for file in response_json.get("files"):
                file_sizes.append(file["size"])

            # Store filenames
            filenames += dataset_filenames

            # If the result is not truncated, we retrieved all filenames
            is_truncated = response_json.get("isTruncated")
            if not is_truncated:
                logger.info("Retrieved names of all dataset files")
                break

            start_after_filename = dataset_filenames[-1]

        logger.info(f"Number of files to download: {len(filenames)}")

        worker_count = get_max_worker_count(file_sizes)
        loop = asyncio.get_event_loop()

        # Allow up to 10 separate threads to download dataset files concurrently
        executor = ThreadPoolExecutor(max_workers=worker_count)
        futures = []

        # Create tasks that download the dataset files
        for dataset_filename in filenames:
            # Create future for dataset file
            future = loop.run_in_executor(
                executor,
                download_dataset_file,
                session,
                base_url,
                dataset_name,
                dataset_version,
                dataset_filename,
                download_directory,
                overwrite,
            )
            futures.append(future)

        # # Wait for all tasks to complete and gather the results
        future_results = await asyncio.gather(*futures)
        logger.info(f"Finished '{dataset_name}' dataset download")

        failed_downloads = list(filter(lambda x: not x[0], future_results))

        if len(failed_downloads) > 0:
            logger.warning("Failed to download the following dataset files:")
            logger.warning(list(map(lambda x: x[1], failed_downloads)))

    if __name__ == "__main__":
        asyncio.run(main())

## Dataset management

To upload files to a dataset, follow these steps:

1.  Create an account on our Developer Portal,
2.  Use your Developer account to request an API key for the Data Content API.
3.  To complete your key request, a form appears where you provide information for the following input fields:

    1.  `Dataset name`: name of the dataset;
    2.  `Data version`: version of the dataset;
    3.  `Comments (Optional)`: additional information for your key request.

Submit the key request once the form contains the required information.

1.  Once we approve your key request, you retrieve an email with your API Key and HMAC secret.

Once you obtained an API Key and HMAC secret, you are ready to upload dataset files to your requested dataset. The script below uploads all files in the provided directory. To periodically upload newly available files it is recommended to create a scheduled task to run the following script. Each operating system has a different built-in scheduler: for Windows use Task Scheduler, for Linux use cron jobs and for MacOS use Scheduler.

### Upload files in a directory to a dataset

    import asyncio
    import base64
    import hashlib
    import hmac
    import logging
    import os
    import urllib.parse
    from concurrent.futures import ThreadPoolExecutor
    from datetime import datetime
    from datetime import timezone
    from pathlib import Path
    from typing import Tuple

    import requests

    logging.basicConfig()
    logger = logging.getLogger(__name__)
    logger.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))

    def upload_file_to_dataset(
        base_url: str,
        api_key: str,
        api_secret: str,
        dataset_name: str,
        dataset_version: str,
        filename: str,
        directory: str,
    ) -> Tuple[bool, str]:
        content_type = "application/text"

        dataset_file_content = Path(f"{directory}/{filename}").read_bytes()
        md5_hash_bytes = hashlib.md5(dataset_file_content).digest()
        md5_hash_b64 = base64.b64encode(md5_hash_bytes).decode("utf-8")

        params = {
            "filename": filename,
            "datasetFileContentType": content_type,
            "md5": md5_hash_b64,
        }
        endpoint = f"{base_url}/{dataset_name}/versions/{dataset_version}/files/uploadUrl"
        headers = generate_signature_headers(api_key, api_secret.encode("utf-8"))

        upload_url_response = requests.get(endpoint, headers=headers, params=params)

        # retrieve upload URL for dataset file
        if upload_url_response.status_code != 200:
            logger.warning(f"Unable to get upload url for :{filename}")
            logger.warning(upload_url_response.content)
            return False, filename

        upload_url = upload_url_response.json()["temporaryUploadUrl"]

        # max file size supported by Python requests library 2.14 gb
        # in the future we will support bigger files using Multipart upload
        headers = {"Content-MD5": md5_hash_b64, "Content-Type": content_type}
        logger.info(f"Start file upload for: {filename}")
        upload_response = requests.put(upload_url, data=dataset_file_content, headers=headers)

        if upload_response.status_code != 200:
            logger.warning(f"Unable to upload file: {filename}")
            logger.warning(upload_response.content)
            return False, filename

        logger.info(f"Upload of '{filename}' successful")
        return True, filename

    def generate_signature_headers(key_id: str, hmac_secret_key: bytearray):
        now_utc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %Z")

        signature_string = f"date: {now_utc}".encode("utf-8")

        hmac_digest = hmac.new(hmac_secret_key, signature_string, hashlib.sha512).digest()
        hmac_digest_b64 = base64.b64encode(hmac_digest).decode("utf-8")
        hmac_digest_b64_url_encoded = urllib.parse.quote_plus(hmac_digest_b64)

        return {
            "Date": now_utc,
            "Authorization": f'Signature keyId="{key_id}",algorithm="hmac-sha512",'
            f'signature="{hmac_digest_b64_url_encoded}" ',
        }

    async def main():
        api_key = "<API_KEY>"
        hmac_secret = "<API_SECRET>"
        dataset_name = "<DATASET_NAME>"
        dataset_version = "<DATASET_VERSION>"
        base_url = "https://api.dataplatform.knmi.nl/dataset-content/v1/datasets"

        # folder that contains the files to be uploaded
        upload_directory = "./my-dataset-files"

        # Verify that the directory exists
        if not Path(upload_directory).is_dir():
            raise Exception(f"Invalid or non-existing directory: {upload_directory}")

        loop = asyncio.get_event_loop()

        # Allow up to 20 separate threads to upload dataset files concurrently
        executor = ThreadPoolExecutor(max_workers=20)
        futures = []

        # Create tasks that upload the dataset files
        folder_content = Path(upload_directory).glob("*")
        files_to_upload = [x for x in folder_content if x.is_file()]
        logger.info(f"Number of files to upload: {len(files_to_upload)}")
        for file_to_upload in files_to_upload:
            # Create future for dataset file
            future = loop.run_in_executor(
                executor,
                upload_file_to_dataset,
                base_url,
                api_key,
                hmac_secret,
                dataset_name,
                dataset_version,
                file_to_upload.name,
                upload_directory,
            )
            futures.append(future)

        # Wait for all tasks to complete and gather the results
        future_results = await asyncio.gather(*futures)
        logger.info(f"Finished '{dataset_name}' uploading")

        failed_uploads = list(filter(lambda x: not x[0], future_results))

        if len(failed_uploads) > 0:
            logger.warning("Failed to upload the following dataset files")
            logger.warning(list(map(lambda x: x[1], failed_uploads)))

    if __name__ == "__main__":
        asyncio.run(main())
