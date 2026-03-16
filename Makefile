NAME = inquisitor


all: build

build:
	docker compose up --build 

bash-victime:
	docker exec -it victime sh


bash-attaquant:
	docker exec -it attaquant sh


bash-serveur:
	docker exec -it serveur sh

clean:
	@docker compose down 2>/dev/null || true
	@echo "Containers stop."

fclean: clean
	@docker compose down --rmi all --volumes
	@echo "Image and container delete with success."


re: fclean build

.PHONY: all build bash-victime bash-attaquant bash-serveur clean fclean
