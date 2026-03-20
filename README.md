# mthesis-distributed-provenance-search

This project was developed as part of my master's thesis. The result consists of 2 services: <b>traversal-service</b> and <b>prov-access-service</b>, that together provide federated search of provenance chains.

<h2>Project structure:</h2>

`/bundle-search`: implementation of <b>prov-access-service</b>.   
`/distributed-provenance-search`: implementation of <b>traversal-service</b>.   
`/prov-storage`: implementation of provenance storage and trusted party from https://gitlab.fi.muni.cz/xmojzis1/provenance-system-tests.  
`/query-structure`: contains diagrams explaining the queries structure.  
`/setup`: contains scripts and data for demo setup.  

<h2>Demo setup:</h2>

Download the repo files or clone the repo.'/

Build the docker images for trusted party and provenance storage from working directory `/prov-storage/` with  
```sh
docker build -f Dockerfile.TrustedParty -t trusted_party .
```  
```sh
docker build -f Dockerfile.ProvStorage -t distributed_prov_system .
```

Build the docker image for traversal service from working directory `/distributed-provenance-search/` with  
```sh
docker build -f Dockerfile -t traversal_service_image .
```

Build the docker image for prov-access service from working directory `/bundle-search/` with  
```sh
docker build -f Dockerfile -t prov-access_service_image .
```

Start docker and from the project root directory run
```sh
docker-compose up -d
```

Run the following command from directory `./setup` to register organizations and upload provenance files for the demo (if you get `curl: (52) Empty reply from server`, wait a few seconds and try again)
```sh
./simulation_setup.sh
```
 It might take a minute untill all the containers are runing and all the services are fully initialized.

<h2>Services</h2>

<h3>traversal-service</h3> 

- Service that traverses the provenance chain in the given direction. It fetches results of a given query for individual bundles in the chain from their respective provenance controllers (prov-access-service containers).
- Swagger UI\*: 
`http://localhost:8090/swagger-ui/index.html#`

<h3>prov-access-service</h3>  

- Service that should be operated under a provenance controller and can answer queries about individual bundles in storage of this provenance controller.  
- Swager UI\*: `http://localhost:8081/swagger-ui/index.html#` 

The swagger UIs provide multiple executable query examples to test the demo.

See the <b>traversal-service</b> API to list available validity checks and traversal priorities. 
Queries are explained further in this readme.

For version preference, two options are available: "SPECIFIED" and "LATEST". 

Authorization is mocked. To be granted access to all bundles, use bearer token "full_access_token". One other token is recognized: "denied_processing_bundle_access", for demonstrating behaviour when access to a bundle is denied.

You can also run requests to the traversal-service and prov-access-service containers from the <b>debug-shell</b> container.

\*<i> Note that the service containers must be running for the Swagger UI to load.</i>  

<h2>Query structure</h2>
Following diagrams contain information relevant for structuring a query. The methods declared in the interfaces are ommited in their implementations to save space and put emphasis on the fields that are used to specify a query.

Possible <i>Kind</i> values are listed here: https://javadoc.io/doc/org.openprovenance.prov/prov-model/latest/prov.model/org/openprovenance/prov/model/StatementOrBundle.Kind.html
<br>
<br>

![IQuery interface implementations](./query-structure/iquery.drawio.svg)  

![IFindableInDocument interface implementations](./query-structure/ifindableindocument.drawio.svg)  
    
![ICondition interface implementations](./query-structure/icondition.drawio.svg)

<h2>Demo data</h2>

The demo data can be found in `./setup/data/` folder. Below is a schema of traversal information of the bundles, excluding sender and reciever agent nodes (to save space). Main activies are depicted as rectangles, and connectors are depicted as ovals. connectors to the left of the main activity are backwad connectors. Connectors to the right of the main acitivyt are forward connectors. Diagrams visualizing the whole content of bundles can be found in `./setup/data/visualized/`. The diagrams were taken from https://is.muni.cz/th/sv0z0/?lang=en and slightly edited (see `./setup/data/visualized/credits.txt`).

![Demo bundles TI scheme](./setup/data/visualized/demo-data-backbone.drawio.svg)

 <h2>Technical issues with storage service and ProvToolbox</h2>
This is a list of issues encountered when working with the Prov Storage implemented in Python and ProvToolbox Java library.

- Issue: In the meta document returned by the storage, ID of the entity representing a version does not match the represented bundle ID. This is not compliant with CPM.  
Fix: Changed the entity id namespaceUri generation in
`prov-storage\distributed_prov_system\provenance\neomodel2prov.py ln 92`.

- Issue: Some values in the meta documents returned by the storage are not in quotes. As a result, ProvToolbox library fails to deserialize the document.  
Fix: Created a method that surrounds values in a JSON with quotes, if they were not in quotes already. Used this method before deserialization of a JSON document.

- Issue: When retrieving only the traversal information of a bundle from storage, {\ttfamily prov:type} attribute value is serialized in format: { "cpm:forwardConnector", "prov:QUALIFIED_NAME" } instead of expected format { "$": "cpm:forwardConnector", "type": "prov:QUALIFIED_NAME" } ProvToolboc then deserializes this as multiple string values of the attribute instead of a typed value.  
Fix: Created a method that takes a JSON document and reformats prov:type values. Used this method before each deserialization of a JSON document.  

- Issue: ProvToolbox library fails to load string attribute values that are not in an array.  
Fix: Created a method that takes a JSON document and puts attribute values into an array if it is not an array already. Used this method before each deserialization of a JSON document.

- Issue: ProvToolbox demands explicit bundle id property as "@id" in JSON documents during deserialization. It also includes the "@id" property during serialization. This is not compliant with the PROV-JSON serialization standard and causes interoperability issues.  
Fix: Created methods that add/remove the "@id" property in JSON. Used relevant method before deserialization and after serialization of a document.

- Issue: ProvToolbox does not load bundle id namespaceUri during deserialization unless prefixes are defined inside the bundle entity.  
Fix: Created a method that copies prefixes from the document into the bundle entity. Used the method before each deserialization of a document.  

- Issue: ProvToolbox fails to deserialize documents from the testing dataset as long as they contain namespace "blank": "https://openprovenance.org/blank#" with # at the end. Suspiciously, other namespaces that contain # at the end were not causing issues.   
Fix: Replaced # at the end of the prefix with /.

- Issue: Trusted party endpoint for retrieving tokens of a specific bundle always results in an error.
FFix: Used the endpoint for retrieving all tokens under an organization instead.