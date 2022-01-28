import React, { useContext, useEffect, useState } from "react";
import ContactContext from "../../context/contact/contactContext";

const initialContact = {
	name: "",
	email: "",
	phone: "",
	type: "personal",
};

const ContactForm = () => {
	const contactContext = useContext(ContactContext);

	const { addContact, current, clearCurrent, updateContact } = contactContext;

	const [contact, setContact] = useState(initialContact);

	useEffect(() => {
		if (current !== null) {
			setContact(current);
		} else {
			setContact(initialContact);
		}
	}, [current]);

	const { name, email, phone, type } = contact;

	const onChange = (e) => {
		setContact({ ...contact, [e.target.name]: e.target.value });
	};

	const onSubmit = (e) => {
		e.preventDefault();
		if (current === null) {
			addContact(contact);
			setContact(initialContact);
		} else {
			updateContact(contact);
		}
		clearAll();
	};

	const clearAll = () => {
		clearCurrent();
	};

	return (
		<form onSubmit={onSubmit}>
			<h2 className='text-primary'>
				{current ? "Edit Contact" : "Add Contact"}
			</h2>
			<input
				type='text'
				name='name'
				placeholder='Name'
				value={name}
				onChange={onChange}
			/>
			<input
				type='email'
				name='email'
				placeholder='Email'
				value={email}
				onChange={onChange}
			/>
			<input
				type='text'
				name='phone'
				placeholder='Phone'
				value={phone}
				onChange={onChange}
			/>
			<h5>Contact Type</h5>
			<input
				type='radio'
				name='type'
				value='personal'
				checked={type === "personal"}
				onChange={onChange}
			/>
			Personal{" "}
			<input
				type='radio'
				name='type'
				value='professional'
				checked={type === "professional"}
				onChange={onChange}
			/>{" "}
			Professional
			<div>
				<input
					type='submit'
					value={current ? "Update Contact" : "Add Contact"}
					className='btn btn-primary btn-block'
				/>
			</div>
			{current && (
				<div>
					<button className='btn btn-light btn-block' onClick={clearAll}>
						Clear
					</button>
				</div>
			)}
		</form>
	);
};

export default ContactForm;
