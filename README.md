# Dust Strike Force
## Conda env Streamlit+Fastapi+sql+jwt with Docker 

---

### Table of Contents

* [Made with](#Made_with)
* [Instructions](#Instructions)

### Made with

* [Streamlit](https://streamlit.io/) - Streamlit is a Python library that simplifies the creation of web applications for data science and machine learning, enabling developers to quickly convert data processing scripts into shareable web applications.
* [FastAPI](https://fastapi.tiangolo.com/) -  FastAPI is a modern, high-performance web framework for building application programming interface (API) interfaces using Python.
* [SQLite](https://www.sqlalchemy.org/) -  SQLite is a lightweight and self-contained relational database widely used for embedded systems and small-scale applications.
* [Docker](https://www.docker.com/) -  Docker is a platform for writing containerized applications.

### Instructions

You will need Docker Desktop to run it: 
https://www.docker.com/products/docker-desktop/


To run it: 
```sh
`docker pull petzen21/force_frontend:2.0.8`
`docker pull petzen21/force_backend:2.0.5`
`docker pull petzen21/postgres:latest`
`docker compose up`

```
User visits: http://localhost:8072/
