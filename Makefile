NAME = inquisitor


all: build run addr addr_ssh

build:
	docker compose up --build 

bash-vitctime:
	docker exec -it victime bash


bash-attaquant:
	docker exec -it attaquant bash


bash-serveur:
	docker exec -it serveur bash

clean:
	@docker compose down 2>/dev/null || true
	@echo "Containers stop."

fclean: clean
	@docker compose down --rmi all --volumes
	@echo "Image and container delete with success."


re: fclean build

.PHONY: all build bash-victime bash-attaquant bash-serveur clean fclean
