PGDMP      +        
        |           DSS_002    16.2    16.2 -               0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false                       0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false                       0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false                       1262    16397    DSS_002    DATABASE     �   CREATE DATABASE "DSS_002" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_United States.1252';
    DROP DATABASE "DSS_002";
                postgres    false            �            1255    16445    update_timestamp()    FUNCTION     �   CREATE FUNCTION public.update_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  NEW.updated_at := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$;
 )   DROP FUNCTION public.update_timestamp();
       public          postgres    false            �            1259    16448    comments    TABLE       CREATE TABLE public.comments (
    id integer NOT NULL,
    post_id integer,
    user_id integer,
    content text NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.comments;
       public         heap    postgres    false            �            1259    16447    comments_id_seq    SEQUENCE     �   CREATE SEQUENCE public.comments_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.comments_id_seq;
       public          postgres    false    222                       0    0    comments_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.comments_id_seq OWNED BY public.comments.id;
          public          postgres    false    221            �            1259    16430    posts    TABLE       CREATE TABLE public.posts (
    id integer NOT NULL,
    user_id integer,
    title character varying(200) NOT NULL,
    content text NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.posts;
       public         heap    postgres    false            �            1259    16429    posts_id_seq    SEQUENCE     �   CREATE SEQUENCE public.posts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.posts_id_seq;
       public          postgres    false    220                       0    0    posts_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.posts_id_seq OWNED BY public.posts.id;
          public          postgres    false    219            �            1259    16411    sessions    TABLE     �   CREATE TABLE public.sessions (
    id integer NOT NULL,
    user_id integer,
    session_token character varying(150) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone
);
    DROP TABLE public.sessions;
       public         heap    postgres    false            �            1259    16410    sessions_id_seq    SEQUENCE     �   CREATE SEQUENCE public.sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.sessions_id_seq;
       public          postgres    false    218                        0    0    sessions_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.sessions_id_seq OWNED BY public.sessions.id;
          public          postgres    false    217            �            1259    16399    users    TABLE       CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(50) NOT NULL,
    email character varying(50) NOT NULL,
    password character varying(100) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    16398    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    216            !           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    215            g           2604    16472    comments id    DEFAULT     j   ALTER TABLE ONLY public.comments ALTER COLUMN id SET DEFAULT nextval('public.comments_id_seq'::regclass);
 :   ALTER TABLE public.comments ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    222    221    222            d           2604    16473    posts id    DEFAULT     d   ALTER TABLE ONLY public.posts ALTER COLUMN id SET DEFAULT nextval('public.posts_id_seq'::regclass);
 7   ALTER TABLE public.posts ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    220    219    220            b           2604    16474    sessions id    DEFAULT     j   ALTER TABLE ONLY public.sessions ALTER COLUMN id SET DEFAULT nextval('public.sessions_id_seq'::regclass);
 :   ALTER TABLE public.sessions ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    217    218    218            `           2604    16475    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    215    216    216                      0    16448    comments 
   TABLE DATA           Y   COPY public.comments (id, post_id, user_id, content, created_at, updated_at) FROM stdin;
    public          postgres    false    222   �3                 0    16430    posts 
   TABLE DATA           T   COPY public.posts (id, user_id, title, content, created_at, updated_at) FROM stdin;
    public          postgres    false    220   �3                 0    16411    sessions 
   TABLE DATA           V   COPY public.sessions (id, user_id, session_token, created_at, expires_at) FROM stdin;
    public          postgres    false    218   o4                 0    16399    users 
   TABLE DATA           J   COPY public.users (id, username, email, password, created_at) FROM stdin;
    public          postgres    false    216   �4       "           0    0    comments_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.comments_id_seq', 1, false);
          public          postgres    false    221            #           0    0    posts_id_seq    SEQUENCE SET     :   SELECT pg_catalog.setval('public.posts_id_seq', 5, true);
          public          postgres    false    219            $           0    0    sessions_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.sessions_id_seq', 1, false);
          public          postgres    false    217            %           0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 14, true);
          public          postgres    false    215            z           2606    16457    comments comments_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.comments
    ADD CONSTRAINT comments_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.comments DROP CONSTRAINT comments_pkey;
       public            postgres    false    222            x           2606    16439    posts posts_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.posts
    ADD CONSTRAINT posts_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.posts DROP CONSTRAINT posts_pkey;
       public            postgres    false    220            r           2606    16417    sessions sessions_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.sessions DROP CONSTRAINT sessions_pkey;
       public            postgres    false    218            t           2606    16419 #   sessions sessions_session_token_key 
   CONSTRAINT     g   ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_session_token_key UNIQUE (session_token);
 M   ALTER TABLE ONLY public.sessions DROP CONSTRAINT sessions_session_token_key;
       public            postgres    false    218            l           2606    16409    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    216            n           2606    16405    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    216            p           2606    16407    users users_username_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_username_key;
       public            postgres    false    216            u           1259    16471    index_posts_created_at    INDEX     N   CREATE INDEX index_posts_created_at ON public.posts USING btree (created_at);
 *   DROP INDEX public.index_posts_created_at;
       public            postgres    false    220            v           1259    16470    index_posts_user_id    INDEX     H   CREATE INDEX index_posts_user_id ON public.posts USING btree (user_id);
 '   DROP INDEX public.index_posts_user_id;
       public            postgres    false    220            j           1259    16469    index_users_username    INDEX     J   CREATE INDEX index_users_username ON public.users USING btree (username);
 (   DROP INDEX public.index_users_username;
       public            postgres    false    216            �           2620    16468 *   comments trigger_update_comments_timestamp    TRIGGER     �   CREATE TRIGGER trigger_update_comments_timestamp BEFORE UPDATE ON public.comments FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();
 C   DROP TRIGGER trigger_update_comments_timestamp ON public.comments;
       public          postgres    false    222    223                       2620    16446    posts trigger_update_timestamp    TRIGGER        CREATE TRIGGER trigger_update_timestamp BEFORE UPDATE ON public.posts FOR EACH ROW EXECUTE FUNCTION public.update_timestamp();
 7   DROP TRIGGER trigger_update_timestamp ON public.posts;
       public          postgres    false    220    223            }           2606    16458    comments comments_post_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.comments
    ADD CONSTRAINT comments_post_id_fkey FOREIGN KEY (post_id) REFERENCES public.posts(id) ON DELETE CASCADE;
 H   ALTER TABLE ONLY public.comments DROP CONSTRAINT comments_post_id_fkey;
       public          postgres    false    220    222    4728            ~           2606    16463    comments comments_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.comments
    ADD CONSTRAINT comments_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 H   ALTER TABLE ONLY public.comments DROP CONSTRAINT comments_user_id_fkey;
       public          postgres    false    222    4718    216            |           2606    16440    posts posts_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.posts
    ADD CONSTRAINT posts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 B   ALTER TABLE ONLY public.posts DROP CONSTRAINT posts_user_id_fkey;
       public          postgres    false    216    4718    220            {           2606    16420    sessions sessions_user_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
 H   ALTER TABLE ONLY public.sessions DROP CONSTRAINT sessions_user_id_fkey;
       public          postgres    false    218    4718    216                  x������ � �         �   x�}�I�0E��)� Q�8&�Y�A*�X���"������v�o�1�kj�*��LV0Q�
ȈƩ��q2}y��9��d)�H�?
�~����v�����+%�h9j�BA��{,�2��o�ʍu"�ㅂ�����Y�,�D�Q��'9��, � E]�            x������ � �         �  x�]��r�@F��Y���W`�7JJ
Ʃ�H��E����Ǟ��bU�>���`���
G����^�����˝�o�� >N��2nv�Mj͂����0>,��/����^��gĞ�����������L[�2ſ��|:��"���~�#:H�F��j�ŋeD�w7HYAt��G�b�TT n�:�n_
G���]IX���`�l=9&���]m�/����\׬*/��!�W�&��o�z�)�	3���]hy�*���M�l��q�ꏍ��Qrv�A-��f�.so+>��B�ӏ����*X}�B	����۹�&�����و�!����������&�u*���X;e������6����u ZV�
��Ú��A� q�j���Q�~���K�%�|��l^�++�Y��see�a؟���Sׯ��������0��c�OC��o�_��     