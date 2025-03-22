# ssp
Stupid Secret Pipeline

## Usage
```
ps aux | grep ssp | grep -v grep | awk '{print $2}' | xargs kill -SIGUSR1
```
## TODO:
* [x] decouple connection and pipe 
* [ ] Multi threads
* [ ] All parameters are configurable
* [ ] Support IPv6