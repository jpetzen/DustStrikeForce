import time
import psycopg2

DB_URL = "postgresql://admin:admin@db:5432/cleanDataset"

# Maximum waiting time for the dataset (in seconds)
MAX_WAIT_TIME = 30

def main():
  """
  Waits for the dataset to be available in the database before proceeding.
  """
  wait_start_time = time.time()
  while True:
    try:
      conn = psycopg2.connect(DB_URL)
      cursor = conn.cursor()

      # Replace with your query to check for dataset existence
      cursor.execute("SELECT EXISTS(SELECT 1 FROM dataset_table)")
      exists = cursor.fetchone()[0]

      if exists:
        print("Dataset is ready!")
        break
      else:
        elapsed_time = time.time() - wait_start_time
        if elapsed_time > MAX_WAIT_TIME:
          print(f"Dataset not found after {MAX_WAIT_TIME} seconds. Exiting.")
          exit(1)
        else:
          print("Dataset not found yet. Sleeping for 5 seconds...")
          time.sleep(5)  # Adjust the sleep time as needed

    except (Exception, psycopg2.Error) as e:
      print(f"Error connecting to database or checking dataset: {e}")
      time.sleep(5)  # Wait and retry on error

    finally:
      if cursor:
        cursor.close()
      if conn:
        conn.close()

if __name__ == "__main__":
  main()