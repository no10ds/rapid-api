import boto3

# Deletes all files in your path so use carefully!


def cleanup_query_files(params):
    session = boto3.Session()
    s3 = session.resource("s3")
    my_bucket = s3.Bucket(params["query_bucket"])
    for item in my_bucket.objects.filter(Prefix=params["query_path"]):
        item.delete()


# Deletes all files in your path so use carefully!
def cleanup_data_files(params):
    session = boto3.Session()
    s3 = session.resource("s3")
    my_bucket = s3.Bucket(params["data_bucket"])
    for item in my_bucket.objects.filter(Prefix=params["data_path"]):
        item.delete()


# Deletes all files in your path so use carefully!
def cleanup_raw_files(params):
    session = boto3.Session()
    s3 = session.resource("s3")
    my_bucket = s3.Bucket(params["data_bucket"])
    for item in my_bucket.objects.filter(Prefix=params["raw_data_path"]):
        item.delete()


def get_file_names(params):
    session = boto3.Session()
    s3 = session.resource("s3")
    my_bucket = s3.Bucket(params["data_bucket"])
    for item in my_bucket.objects.filter(Prefix="raw_data/playwright/playwright01/"):
        if item.key.endswith("test_journey_file.csv"):
            file_name = item.key.split("/")[-1]
            return file_name
        else:
            raise Exception("No file found")
    print("Cleaning up...")
    cleanup_query_files(params)
    cleanup_data_files(params)
    cleanup_raw_files(params)
