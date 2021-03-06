package net.corda.serialization.internal.model

import net.corda.core.serialization.ClassWhitelist
import net.corda.serialization.internal.amqp.*
import java.lang.reflect.*

/**
 * Provides a means for looking up [LocalTypeInformation] by [Type] and [TypeIdentifier], falling back to building it
 * if the lookup can't supply it.
 *
 * The purpose of this class is to make a registry of [LocalTypeInformation] usable by a [LocalTypeInformationBuilder] that
 * recursively builds [LocalTypeInformation] for all of the types visible by traversing the DAG of related types of a given
 * [Type].
 */
interface LocalTypeLookup {

    /**
     * Either return the [LocalTypeInformation] held in the registry for the given [Type] and [TypeIdentifier] or, if
     * no such information is registered, call the supplied builder to construct the type information, add it to the
     * registry and then return it.
     */
    fun findOrBuild(type: Type, typeIdentifier: TypeIdentifier, builder: (Boolean) -> LocalTypeInformation): LocalTypeInformation

    /**
     * Indicates whether a type should be excluded from lists of interfaces associated with inspected types, i.e.
     * because it is not whitelisted.
     */
    fun isExcluded(type: Type): Boolean
}

/**
 * A [LocalTypeModel] maintains a registry of [LocalTypeInformation] for all [Type]s which have been observed within a
 * given classloader context.
 */
interface LocalTypeModel {
    /**
     * Look for a [Type] in the registry, and return its associated [LocalTypeInformation] if found. If the [Type] is
     * not in the registry, build [LocalTypeInformation] for that type, using this [LocalTypeModel] as the [LocalTypeLookup]
     * for recursively resolving dependencies, place it in the registry, and return it.
     *
     * @param type The [Type] to get [LocalTypeInformation] for.
     */
    fun inspect(type: Type): LocalTypeInformation

    /**
     * Get [LocalTypeInformation] directly from the registry by [TypeIdentifier], returning null if no type information
     * is registered for that identifier.
     */
    operator fun get(typeIdentifier: TypeIdentifier): LocalTypeInformation?
}

/**
 * A [LocalTypeLookup] that is configurable with [LocalTypeModelConfiguration], which controls which types are seen as "opaque"
 * and which are "excluded" (see docs for [LocalTypeModelConfiguration] for explanation of these terms.
 *
 * @param typeModelConfiguration Configuration controlling the behaviour of the [LocalTypeModel]'s type inspection.
 */
class ConfigurableLocalTypeModel(private val typeModelConfiguration: LocalTypeModelConfiguration): LocalTypeModel, LocalTypeLookup {

    private val typeInformationCache = DefaultCacheProvider.createCache<TypeIdentifier, LocalTypeInformation>()

    override fun isExcluded(type: Type): Boolean = typeModelConfiguration.isExcluded(type)

    override fun inspect(type: Type): LocalTypeInformation = LocalTypeInformation.forType(type, this)

    override fun findOrBuild(type: Type, typeIdentifier: TypeIdentifier, builder: (Boolean) -> LocalTypeInformation): LocalTypeInformation =
            this[typeIdentifier] ?: builder(typeModelConfiguration.isOpaque(type)).apply {
                typeInformationCache.putIfAbsent(typeIdentifier, this)
            }

    override operator fun get(typeIdentifier: TypeIdentifier): LocalTypeInformation? = typeInformationCache[typeIdentifier]
}

/**
 * Configuration which controls how a [LocalTypeModel] inspects classes to build [LocalTypeInformation].
 */
interface LocalTypeModelConfiguration {
    /**
     * [Type]s which are flagged as "opaque" are converted into instances of [LocalTypeInformation.Opaque] without
     * further inspection - the type model doesn't attempt to inspect their superclass/interface hierarchy, locate
     * constructors or enumerate their properties. Usually this will be because the type is handled by a custom
     * serializer, so we don't need detailed information about it to help us build one.
     */
    fun isOpaque(type: Type): Boolean

    /**
     * [Type]s which are excluded are silently omitted from the superclass/interface hierarchy of other types'
     * [LocalTypeInformation], usually because they are not included in a whitelist.
     */
    fun isExcluded(type: Type): Boolean
}
