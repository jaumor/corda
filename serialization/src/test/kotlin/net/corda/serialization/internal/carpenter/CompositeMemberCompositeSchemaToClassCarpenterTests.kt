package net.corda.serialization.internal.carpenter

import net.corda.core.serialization.CordaSerializable
import net.corda.serialization.internal.AllWhitelist
import org.junit.Test
import java.io.NotSerializableException
import kotlin.test.assertFailsWith

@CordaSerializable
interface I_ {
    val a: Int
}

class CompositeMembers : AmqpCarpenterBase(AllWhitelist) {

    @Test
    fun parentIsUnknown() {
        @CordaSerializable
        data class A(val a: Int)

        @CordaSerializable
        data class B(val a: A, var b: Int)

        val (_, envelope) = B(A(10), 20).roundTrip()

        // We load an unknown class, B_mangled, which includes a reference to a known class, A.
        assertCanLoadAll(envelope.getMangled<B>())
    }

    @Test
    fun bothAreUnknown() {
        @CordaSerializable
        data class A(override val a: Int) : I_

        @CordaSerializable
        data class B(val a: A, var b: Int)

        val (_, envelope) = B(A(10), 20).roundTrip()

        // We load an unknown class, B_mangled, which includes a reference to an unknown class, A_mangled.
        // For this to work, we must include A_mangled in our set of classes to load.
        assertCanLoadAll(envelope.getMangled<B>().mangle<A>(), envelope.getMangled<A>())
    }

    @Test
    fun oneIsUnknown() {
        @CordaSerializable
        data class A(override val a: Int) : I_

        @CordaSerializable
        data class B(val a: A, var b: Int)

        val (_, envelope) = B(A(10), 20).roundTrip()

        // We load an unknown class, B_mangled, which includes a reference to an unknown class, A_mangled.
        // This will fail, because A_mangled is not included in our set of classes to load.
        assertFailsWith<NotSerializableException> { assertCanLoadAll(envelope.getMangled<B>().mangle<A>()) }
    }
}
