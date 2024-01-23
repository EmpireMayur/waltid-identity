package id.walt.webwallet.web.controllers

import id.walt.web.controllers.getWalletService
import io.github.smiley4.ktorswaggerui.dsl.get
import io.github.smiley4.ktorswaggerui.dsl.post
import io.github.smiley4.ktorswaggerui.dsl.route
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import kotlinx.serialization.json.JsonObject

fun Application.categories() = walletRoute {
    route("categories", {
        tags = listOf("WalletCategories")
    }) {
        get({
            summary = "List categories"
            response {
                HttpStatusCode.OK to {
                    description = "Array of categories"
                    body<List<JsonObject>>()
                }
            }
        }) {
            context.respond(getWalletService().listCategories())
        }
        route("{name}") {
            post("add", {
                summary = "Add category"
                request {
                    pathParameter<String>("name") {
                        description = "the category name"
                        example = "my-category"
                    }
                }
                response {
                    HttpStatusCode.Created to { description = "Category added" }
                    HttpStatusCode.BadRequest to { description = "Category could not be added" }
                }
            }) {
                val name = call.parameters["name"] ?: throw IllegalArgumentException("No category name provided")
                runCatching { getWalletService().addCategory(name) }.onSuccess {
                    context.respond(if (it) HttpStatusCode.Created else HttpStatusCode.BadRequest)
                }.onFailure { context.respond(HttpStatusCode.BadRequest, it.localizedMessage) }
            }
            post("delete", {
                summary = "Delete category"
                request {
                    pathParameter<String>("name") {
                        description = "the category name"
                        example = "my-category"
                    }
                }
                response {
                    HttpStatusCode.Accepted to { description = "Category delete" }
                    HttpStatusCode.BadRequest to { description = "Category could not be deleted" }
                }
            }) {
                val name = call.parameters["name"] ?: throw IllegalArgumentException("No category name provided")
                runCatching { getWalletService().deleteCategory(name) }.onSuccess {
                    context.respond(if (it) HttpStatusCode.Accepted else HttpStatusCode.BadRequest)
                }.onFailure { context.respond(HttpStatusCode.BadRequest, it.localizedMessage) }
            }
        }
    }
}