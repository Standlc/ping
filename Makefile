NAME		=	ping

SRCS		=	main.c								signal.c \

OBJS		=	$(SRCS:.c=.o)

CC			=	cc

CFLAGS		=	-Wall -Wextra -Werror

RM			=	rm -f

all: libs $(NAME)

$(NAME): $(OBJS)
		$(CC) $(OBJS) -o $(NAME)

%.o: %.c ft_ping.h Makefile
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		@$(RM) $(OBJS)

fclean:	clean
		@$(RM) $(NAME)

re:		fclean all

.PHONY: all libs clean fclean re