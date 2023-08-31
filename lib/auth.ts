import { NextAuthOptions } from "next-auth";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { db } from "@/lib/db";
import { db as prisma } from "@/lib/db";

import CredentialProvider from "next-auth/providers/credentials"
import GitHubProvider from "next-auth/providers/github"
import bcrypt from "bcrypt";



export const authOptions : NextAuthOptions = {
    // @see https://github.com/prisma/prisma/issues/16117
    adapter: PrismaAdapter(db as any),
    providers: [

        GitHubProvider({
            clientId: process.env.GITHUB_CLIENTID!,
            clientSecret: process.env.GITHUB_SECRET!
        }),

        CredentialProvider({
            name: "credentials",
            credentials: {
                email: {label: "Email", type: "text", placeholder: "Lisboa"},
                password: {label: "Password", type: "password"},
                username: {label: "Username", type: "text", placeholder: "Wanderson"}
            },

            async authorize(credentials, req) : Promise<any> {

                console.log("Authorize method", credentials)

                if (!credentials?.email || !credentials?.password) {
                    throw new Error("Dados de Login necessarios")
                }

                const user = await prisma.user.findUnique({
                    where: {
                        email: credentials?.email
                    }
                })

                if (!user || !user.hashedPassword) {
                    throw new Error("Usuário não Registrado através de credenciais");
                }

                const matchPassword = await bcrypt.compare(credentials.password, user.hashedPassword);
                if (!matchPassword) {
                    throw new Error("Senha incorreta")
                }

                return user;
            }
        })
    ],
    session: {
        strategy: "jwt"
    },
    secret: process.env.SECRET,
    debug: process.env.NODE_ENV === "development",
    pages: {
        signIn: "/login",
    }
}